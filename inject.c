#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <stdio.h>
#include <stdarg.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <time.h>
#include <linux/version.h>
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mount.h>
#include <sched.h>

#include <openssl/evp.h>
#include <lzma.h>

#include "cached_info.h"

/* Since the display seems a bit delicate, prefer to kill xochitl if
 * something goes wrong---it seems less likely to cause damage given
 * prevent_frying_pan than allowing xochitl to continue in some
 * undefined state.
 */
int kill_fb_proc_when_dying = -1;
/* Similarly, but for the process that we use to get a name for the
 * unix socket.
 */
int kill_binder_when_dying = -1;
static void diep(char *words) {
  perror(words);
  if (kill_fb_proc_when_dying != -1) { kill(kill_fb_proc_when_dying, SIGKILL); }
  if (kill_binder_when_dying != -1) { kill(kill_binder_when_dying, SIGKILL); }
  exit(1);
}

static void die(const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  if (kill_fb_proc_when_dying != -1) { kill(kill_fb_proc_when_dying, SIGKILL); }
  if (kill_binder_when_dying != -1) { kill(kill_binder_when_dying, SIGKILL); }
  exit(1);
}

struct dyn_info {
  pid_t pid;
  struct cached_state *cached;
  uint qimage_bits_addr;
  uint mmap_addr;
  uint su_preamble[N_PREAMBLE_INSTRS];

  pid_t socket_binder_pid;
  int socket_fd;
  uint scratch_page;

  uint fb_bits_addr;
  int fb_fd;
};

static pid_t find_process(void) {
  struct stat sbf;
  if (stat("/dev/fb0", &sbf)) { diep("stat fb0"); }
  DIR *d = opendir("/proc");
  if (!d) { diep("proc"); }
  errno = 0;
  pid_t fbpid = 0;
  struct dirent *de;
  while (de = readdir(d)) {
    pid_t pid = 0;
    for (char* p = de->d_name; *p; p++) {
      if ('0' > *p || '9' << *p) { goto bad_dir_0; }
      pid *= 10;
      pid += *p-'0';
    }
    char *fdn;
    if (asprintf(&fdn, "/proc/%s/fd/", de->d_name) < 0) { goto bad_dir_0; };
    if (!fdn) { die("asprint failed\n"); }
    DIR *fdd = opendir(fdn);
    if (!fdd) { goto bad_dir_1; }
    errno = 0;
    struct dirent *fde;
    while (fde = readdir(fdd)) {
      char *p;
      for (p = fde->d_name; *p; p++) {
        if ('0' > *p || '9' << *p) { break; }
      }
      if (*p) { continue; }
      struct stat fdsbf;
      char *fdpath = NULL;
      if (asprintf(&fdpath, "/proc/%s/fd/%s", de->d_name, fde->d_name) < 0) {
        errno = 0; continue;
      }
      if (stat(fdpath, &fdsbf)) { errno = 0; continue; }
      if (sbf.st_dev == fdsbf.st_dev && sbf.st_ino == fdsbf.st_ino) {
        fbpid = pid;
        closedir(fdd);
        free(fdpath);
        free(fdn);
        goto found_entry;
      }
      errno = 0;
    }
    closedir(fdd);
 bad_dir_1:
    free(fdn);
 bad_dir_0:
    errno = 0;
  }
  if (errno) { diep("proc entry"); }
found_entry:
  if (!fbpid) { die("no process using fb0!\n"); }
  closedir(d);
  return fbpid;
}

#define CACHE_DIR_ENV "LIBQSGEPAPER_SNOOP_CACHE_DIR"
#define DEFAULT_CACHE_DIR "/home/root/.cache/libqsgepaper-snoop"
char *find_cache_file(struct dyn_info *info, const char *exename) {
  char *prefix = getenv(CACHE_DIR_ENV);
  if (!prefix) { prefix = DEFAULT_CACHE_DIR; }
  size_t file_name_size = EVP_MAX_MD_SIZE*2+strlen(prefix)+1;
  char *cache_file_name = malloc(file_name_size);
  if (!cache_file_name) { diep("malloc cache_file_name"); }
  strcpy(cache_file_name, prefix);

  int fd = open(exename, O_RDONLY);
  if (fd < 0) { diep("open"); }
  struct stat stat;
  if (fstat(fd, &stat)) { diep("stat"); }
  char *x = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (x == MAP_FAILED) { diep("mmap"); }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_create();
  if (!mdctx) { die("md_ctx_new"); }
  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) { die("digestinit"); }
  if (EVP_DigestUpdate(mdctx, x, stat.st_size) != 1) { die("digestupdate"); }
  size_t digest_len;
  char *digest_start = &cache_file_name[file_name_size-EVP_MAX_MD_SIZE];
  if (EVP_DigestFinal_ex(mdctx, digest_start, &digest_len) != 1) { die("digestfinal"); }
  EVP_MD_CTX_destroy(mdctx);

  cache_file_name[strlen(prefix)] = '/';
  for (int i = 0; i < digest_len; ++i) {
    sprintf(cache_file_name+strlen(prefix)+1+2*i, "%02x", digest_start[i]);
  }

  munmap(x, stat.st_size);
  close(fd);

  return cache_file_name;
}

#define EXTRACT_INFO_ENV "LIBQSGEPAPER_SNOOP_EXTRACT_INFO"
char __attribute__((weak)) extract_info_begin = 0;
char __attribute__((weak)) extract_info_end = 0;
static void extract_cached_info(struct dyn_info *info, char *cache_path) {
  char *external = getenv(EXTRACT_INFO_ENV);
  int fd;
  char *start = &extract_info_begin;
  size_t size = &extract_info_end - &extract_info_begin;
  char *exe;
  if (external) {
    exe = external;
  } else {
    printf("Uncompressing extraction program\n");
    /* check for first character of XZ magic */
    if (*start != 0xFD) { die("Need an extract_info binary!\n"); }

    fd = memfd_create("extract_info", 0);
    lzma_stream strm = LZMA_STREAM_INIT;
    lzma_ret ret = lzma_stream_decoder(&strm, UINT64_MAX, 0);
    if (ret != LZMA_OK) { die("lzma_stream_decoder %u\n", ret); }
    strm.next_in = start;
    strm.avail_in = size;
    char outbuf[BUFSIZ];
    while (1) {
      strm.next_out = outbuf;
      strm.avail_out = sizeof(outbuf);
      ret = lzma_code(&strm, LZMA_RUN);
      size_t len = sizeof(outbuf) - strm.avail_out;
      char *p = outbuf;
      if (!strm.avail_out || ret == LZMA_STREAM_END) {
        while (len > 0) {
          size_t n = write(fd, p, len);
          len -= n;
          p += n;
        }
      }
      if (ret != LZMA_OK) {
        if (ret == LZMA_STREAM_END) { break; }
        else { die("lzma_code %u\n", ret); }
      }
    }
    if (asprintf(&exe, "/proc/self/fd/%d", fd) < 0) { die("asprintf exe\n"); }
  }

  int child = fork();
  if (child < 0) { diep("fork"); }
  if (!child) {
    printf("Running extraction pass %d\n", getpid());
    char *pid;
    if (asprintf(&pid, "%d", info->pid) < 0) { die("asprintf pid\n"); };
    char *const argv[] = { exe, pid, cache_path, NULL };
    execve(exe, argv, NULL);
  } else {
    int status;
    while (child != waitpid(child, &status, 0) || !WIFEXITED(status)) {};
  }

  if (!external) {
    madvise(start, size, MADV_DONTNEED);
    close(fd);
  }
}

static void read_all(int fd, void *buf, size_t size) {
  do {
    int n = read(fd, buf, size);
    if (n < 0) {
      if (errno == EINTR) { continue; }
      else { diep("read"); }
    }
    buf += n; size -= n;
  } while (size > 0);
}
static void load_cached_info(struct dyn_info *info) {
  char *exename;
  if (asprintf(&exename, "/proc/%d/exe", info->pid) < 0) {
    die("asprintf failed\n");
  }
  if (!exename) { die("asprint failed\n"); }
  char *cache_path = find_cache_file(info, exename);

  if (faccessat(AT_FDCWD, cache_path, F_OK, AT_EACCESS) != 0) {
    printf("No cached info found for %s\n", exename);
    extract_cached_info(info, cache_path);
  }

  int fd = open(cache_path, O_RDONLY);
  if (fd < 0) { diep("open cache"); }
  char magic[sizeof(HEADER_MAGIC)];
  read_all(fd, magic, sizeof(HEADER_MAGIC));
  if (strcmp(magic, HEADER_MAGIC)) { die("bad magic\n"); }
  uint size;
  read_all(fd, &size, 4);
  info->cached = malloc(size);
  if (!info->cached) { diep("malloc"); }
  read_all(fd, info->cached, size);
}

static void wait_for_stop(pid_t pid, int sig) {
  int status;
  do {
    while (pid != waitpid(pid, &status, 0)) {}
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      die("Framebuffer controlling process %d existed\n", pid);
    }
  } while (!WIFSTOPPED(status) || WSTOPSIG(status) != sig);
}
static void attach(struct dyn_info *info) {
  if (ptrace(PTRACE_ATTACH, info->pid, NULL, NULL)) { diep("attach"); }
  wait_for_stop(info->pid, SIGSTOP);
}

static void get_sendUpdate_preamble(struct dyn_info *info) {
  for (int i = 0; i < N_PREAMBLE_INSTRS; ++i) {
    errno = 0;
    info->su_preamble[i] =
        ptrace(PTRACE_PEEKTEXT, info->pid,
               info->cached->sendUpdate_addr + 4*i, 0);
    if (errno) { diep("peek su instr"); }
  }
  if ((info->su_preamble[0] & 0xFFF0F000) == 0xE300C000 &&
      (info->su_preamble[1] & 0xFFF0F000) == 0xE340C000 &&
      (info->su_preamble[2] == 0xE1A0F00C)) {
    uint addr =
        (info->su_preamble[0] & 0xFFF) |
        ((info->su_preamble[0] >> 4) & 0xF000) |
        ((info->su_preamble[1] & 0xFFF) << 16) |
        ((info->su_preamble[1] & 0xF0000) << 12);
    uint magic[4];
    for (int i = 0; i < 4; ++i) {
      errno = 0;
      magic[i] =
          ptrace(PTRACE_PEEKTEXT, info->pid, addr - 4*INJ_SUPRHK_OFF + 4*i, 0);
      if (errno) { diep("peek su magic"); }
    }
    if (magic[0] == INJ_MAGIC_0 &&
        magic[1] == INJ_MAGIC_1 &&
        magic[2] == INJ_MAGIC_2 &&
        magic[3] == INJ_MAGIC_3) {
      for (int i = 0; i < N_PREAMBLE_INSTRS; ++i) {
        errno = 0;
        info->su_preamble[i] =
            ptrace(PTRACE_PEEKTEXT, info->pid,
                   addr - 4*INJ_SUPRHK_OFF + 4*(INJ_SUPR_OFF + i), 0);
        if (errno) { diep("peek su orig instr"); }
      }
    }
  }
}
static void get_dyn_info(struct dyn_info *info) {
  errno = 0;
  info->qimage_bits_addr = ptrace(PTRACE_PEEKDATA, info->pid,
                                  info->cached->qimage_bits_addr_addr, 0);
  if (errno) { diep("peek qimage_bits addr"); }
  errno = 0;
  info->mmap_addr = ptrace(PTRACE_PEEKDATA, info->pid,
                           info->cached->mmap_addr_addr, 0);
  if (errno) { diep("peek mmap addr"); }

  get_sendUpdate_preamble(info);
}

void check_cached_info(struct dyn_info *info) {
  for (int i = 0; i < info->cached->ncbits; ++i) {
    errno = 0;
    uint rval = ptrace(PTRACE_PEEKDATA, info->pid,
                       info->cached->cbits[i].addr, 0);
    if (rval != info->cached->cbits[i].eval) { die("Bad cache cbit %d\n", i); }
  }
  for (int i = 0; i < N_PREAMBLE_INSTRS; ++i) {
    if (info->su_preamble[i] != info->cached->su_preamble[i]) {
      die("Bad cache preamble %d\n", i);
    }
  }
}

void bind_socket(struct dyn_info *info) {
  info->socket_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
  if (info->socket_fd < 0) { diep("socket"); }
  struct sockaddr_un addr = {0};
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, "socket");

  info->socket_binder_pid = fork();
  if (info->socket_binder_pid < 0) { diep("fork"); }
  if (!info->socket_binder_pid) {
    if (unshare(CLONE_NEWNS)) { diep("unshare"); }
    if (mount("/", "/", "", MS_PRIVATE|MS_REC, 0)) { diep("mount-p"); }
    if (mount("tmpfs", "..", "tmpfs", 0, 0)) { diep("mount-t"); }
    if (chdir("..")) { diep("chdir"); }
    if (bind(info->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      diep("bind");
    }
    while (1) { pause(); }
  }
  kill_binder_when_dying = info->socket_binder_pid;
}

void make_scratch_page(struct dyn_info *info) {
  pid_t pid = info->pid;
  struct user_regs regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs)) { diep("get orig regs"); }
  struct user_regs inj_regs = regs;
  inj_regs.uregs[15] = info->mmap_addr;
  inj_regs.uregs[0] = 0;
  inj_regs.uregs[1] = 4096; // PAGESIZ
  inj_regs.uregs[2] = PROT_READ|PROT_WRITE|PROT_EXEC;
  inj_regs.uregs[3] = MAP_PRIVATE|MAP_ANONYMOUS;
  inj_regs.uregs[13] -= 8;
  if (ptrace(PTRACE_POKEDATA, pid, regs.uregs[13]-8, -1)) { diep("mmap fd"); }
  if (ptrace(PTRACE_POKEDATA, pid, regs.uregs[13]-4, 0)) { diep("mmap off"); }
  if (ptrace(PTRACE_SETREGS, pid, NULL, &inj_regs)) { diep("mmap regs"); };
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 3, 0)
  int need_to_eat_syscall = 0;
#endif
  kill_fb_proc_when_dying = info->pid;
wait_for_syscall_entry:
  if (ptrace(PTRACE_SYSCALL, pid, NULL, 0)) { diep("syscall begin"); };
  wait_for_stop(pid, SIGTRAP);
  siginfo_t sigdata;
  if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &sigdata)) { diep("get siginfo"); }
  if (sigdata.si_code != SIGTRAP) { goto wait_for_syscall_entry; }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
  struct ptrace_syscall_info sysinfo;
  if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(struct ptrace_syscall_info), &sysinfo)) { diep("get sysinfo"); }
  if (sysinfo.op != PTRACE_SYSCALL_INFO_ENTRY ||
      sysinfo.entry.nr != __NR_mmap2 ||
      sysinfo.entry.args[0] != inj_regs.uregs[0] ||
      sysinfo.entry.args[1] != inj_regs.uregs[1] ||
      sysinfo.entry.args[2] != inj_regs.uregs[2] ||
      sysinfo.entry.args[3] != inj_regs.uregs[3] ||
      sysinfo.entry.args[4] != -1 ||
      sysinfo.entry.args[5] != 0) {
    goto wait_for_syscall_entry;
  }
#else
  if (need_to_eat_syscall) {
    need_to_eat_syscall = 0;
    goto wait_for_syscall_entry;
  }
  struct user_regs sys_regs;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &sys_regs)) { diep("get sysin regs"); }
  if (sys_regs.uregs[7] != __NR_mmap2 ||
      sys_regs.uregs[0] != inj_regs.uregs[0] ||
      sys_regs.uregs[1] != inj_regs.uregs[1] ||
      sys_regs.uregs[2] != inj_regs.uregs[2] ||
      sys_regs.uregs[3] != inj_regs.uregs[3] ||
      sys_regs.uregs[4] != -1 ||
      sys_regs.uregs[5] != 0) {
    need_to_eat_syscall = 1;
    goto wait_for_syscall_entry;
  }
#endif
wait_for_syscall_exit:
  if (ptrace(PTRACE_SYSCALL, pid, NULL, 0)) { diep("syscall run"); };
  wait_for_stop(pid, SIGTRAP);
  if (ptrace(PTRACE_GETSIGINFO, pid, NULL, &sigdata)) { diep("get siginfo"); }
  if (sigdata.si_code != SIGTRAP) { goto wait_for_syscall_exit; }
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
  struct ptrace_syscall_info sysinfo;
  if (ptrace(PTRACE_GET_SYSCALL_INFO, pid, sizeof(struct ptrace_syscall_info), &sysinfo)) { diep("get sysinfo"); }
  if (sysinfo.op != PTRACE_SYSCALL_INFO_EXIT) { goto wait_for_syscall_exit; }
  if (sysinfo.exit.is_error) {
    if (sysinfo.exit.rval == -EINTR) { goto wait_for_syscall_entry; }
    else { errno = -sysinfo.exit.rval; diep("mmap failed"); }
  }
  info->scratch_page = rval;
#else
  if (ptrace(PTRACE_GETREGS, pid, NULL, &sys_regs)) { diep("get sysout regs"); }
  if (sys_regs.uregs[0] <= 0 && sys_regs.uregs[0] >= -4095) {
    if (sys_regs.uregs[0] == -EINTR) { goto wait_for_syscall_entry; }
    errno = -sys_regs.uregs[0];
    diep("mmap failed");
  }
  info->scratch_page = sys_regs.uregs[0];
#endif
  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs)) { diep("restore regs"); }
  kill_fb_proc_when_dying = -1;
}

#define INJECTABLE_ENV "LIBQSGEPAPER_SNOOP_PAYLOAD"
uint __attribute__((weak)) injectable_begin = 0;
uint __attribute__((weak)) injectable_end = 0;
void load_injectable(struct dyn_info *info) {
  uint *start = &injectable_begin;
  size_t size = &injectable_end-&injectable_begin;

  char *external = getenv(INJECTABLE_ENV);
  int fd;
  if (external) {
      fd = open(external, O_RDONLY);
      if (fd < 0) { diep("open"); }
      struct stat stat;
      if (fstat(fd, &stat)) { diep("stat"); }
      start = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
      if (start == MAP_FAILED) { diep("mmap"); }
      size = stat.st_size/4;
  }

  if (start[0] != INJ_MAGIC_0 ||
      start[1] != INJ_MAGIC_1 ||
      start[2] != INJ_MAGIC_2 ||
      start[3] != INJ_MAGIC_3) {
    die("Need an injectable payload!\n");
  }

  uint p = info->scratch_page;
  for (size_t i = 0; i < size; ++i) {
    uint buf = start[i];
    if (i == INJ_FBADDR_OFF) { buf = info->cached->fb_addr; }
    if (i == INJ_SKPID_OFF) { buf = info->socket_binder_pid; }
    if (i == INJ_QIB_OFF) { buf = info->qimage_bits_addr; }
    if (i == INJ_SUADDR_OFF) {
      buf = info->cached->sendUpdate_addr + 4*N_PREAMBLE_INSTRS;
    }
    if (i >= INJ_SUPR_OFF && i < INJ_SUPR_OFF+N_PREAMBLE_INSTRS) {
      buf = info->su_preamble[i-INJ_SUPR_OFF];
    }

    if (ptrace(PTRACE_POKEDATA, info->pid, p, buf)) { diep("inject"); }
    p += 4;
  }

  if (external) {
    munmap(start, size);
    close(fd);
  }
}

void steal_frame_buffer(struct dyn_info *info) {
  struct user_regs regs;
  if (ptrace(PTRACE_GETREGS, info->pid, NULL, &regs)) { diep("inj orig regs"); }
  struct user_regs inj_regs = regs;
  inj_regs.uregs[15] = info->scratch_page + 4*INJ_SFB_OFF;

  kill_fb_proc_when_dying = info->pid;
  if (ptrace(PTRACE_SETREGS, info->pid, NULL, &inj_regs)) { diep("inj regs"); }
  if (ptrace(PTRACE_CONT, info->pid, NULL, 0)) { diep("inj cont"); }
  wait_for_stop(info->pid, SIGTRAP);

  uint suprhk = info->scratch_page + 4*INJ_SUPRHK_OFF;
  uint movw = 0xE300C000 | (suprhk & 0xFFF) | (((suprhk >> 12) & 0xF) << 16);
  uint movt = 0xE340C000 | ((suprhk >> 16) & 0xFFF) | ((suprhk >> 28) << 16);
  uint movpc = 0xE1A0F00C;
  uint bxlr = 0xE12FFF1E;
  if (ptrace(PTRACE_POKEDATA, info->pid, info->cached->sendUpdate_addr, bxlr)) {
    diep("bxlr");
  }
  if (ptrace(PTRACE_POKEDATA, info->pid, info->cached->sendUpdate_addr+8, movpc)) {
    diep("movpc");
  }
  if (ptrace(PTRACE_POKEDATA, info->pid, info->cached->sendUpdate_addr+4, movt)) {
    diep("movt");
  }
  if (ptrace(PTRACE_POKEDATA, info->pid, info->cached->sendUpdate_addr, movw)) {
    diep("movw");
  }

  if (ptrace(PTRACE_SETREGS, info->pid, NULL, &regs)) { diep("inj rest regs"); }
  kill_fb_proc_when_dying = -1;
  if (ptrace(PTRACE_DETACH, info->pid, NULL, 0)) { diep("ptrace go away"); }

  kill(info->socket_binder_pid, SIGKILL); /* don't need this anymore! */
  kill_binder_when_dying = -1;

  struct iovec v = {
    .iov_base = &info->fb_bits_addr,
    .iov_len = sizeof(uint),
  };
  struct msghdr msg = { 0 };
  msg.msg_iov = &v;
  msg.msg_iovlen = 1;
  union {
    char buf[CMSG_SPACE(sizeof(int))];
    struct cmsghdr align;
  } u;
  msg.msg_control = u.buf;
  msg.msg_controllen = sizeof(u.buf);
  if (recvmsg(info->socket_fd, &msg, 0) < 0) { diep("recvmsg"); };
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  info->fb_fd = *(int*)CMSG_DATA(cmsg);
}

struct libqsgepaper_snoop_fb libqsgepaper_snoop(void) {
  struct dyn_info info = {
    .pid = find_process(),
  };
  load_cached_info(&info);
  attach(&info);
  get_dyn_info(&info);
  check_cached_info(&info);
  bind_socket(&info);
  make_scratch_page(&info);
  load_injectable(&info);
  steal_frame_buffer(&info);
  struct libqsgepaper_snoop_fb ret = {
    .fb_fd = info.fb_fd,
    .offset = info.fb_bits_addr & 0xFFF,
    .socket_fd = info.socket_fd,
  };
  return ret;
}
