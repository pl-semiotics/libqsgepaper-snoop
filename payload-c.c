#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/mman.h>
#include <signal.h>

#include "private.h"

typedef unsigned int uint;
extern uint _syscall(uint, uint, uint, uint, uint, uint, uint, uint);
extern void trap(void);

#define syscalll(nr, arg1, arg2, arg3, arg4, arg5, arg6, arg7, args...) \
  _syscall(nr, (uint)arg1, (uint)arg2, (uint)arg3, (uint)arg4, (uint)arg5, (uint)arg6, (uint)arg7)
#define syscall(nr, ...) syscalll(nr, ## __VA_ARGS__, 0, 0, 0, 0, 0, 0, 0, 0)

#define MAX_PID_CHARS 7 /* at least right now */
struct sockaddr_un addr = {
  .sun_family = AF_UNIX,
  .sun_path = "/proc/XXXXXXX/cwd/socket",
};

#define FBLEN (1404*1872*2)

__attribute__((section(".magic")))
uint magic[] = {
  INJ_MAGIC_0,
  INJ_MAGIC_1,
  INJ_MAGIC_2,
  INJ_MAGIC_3,
};

__attribute__((section(".cheader0")))
volatile uint fbimgaddr = 0;
__attribute__((section(".cheader1")))
volatile uint skpid = 0;
__attribute__((section(".cheader2")))
volatile uint (*qimage_bits)(uint qimage) = NULL;

uint fbaddr = 0;
uint socketfd = -1;

static void set_socket_path(void) {
  char *p = &addr.sun_path[5+MAX_PID_CHARS];
  while (skpid != 0) {
    *p = '0' + (skpid % 10);
    --p;
    skpid /= 10;
  }
  char *o = &addr.sun_path[5];
  do {
    *++o = *++p;
  } while (*p);
}

#define strlen our_strlen
static size_t strlen(char *str) {
  size_t len = 0;
  while (*str++) { len += 1; }
  return len;
}

static void diep(char *msg, int ret) {
  syscall(__NR_write, 2, msg, strlen(msg));
  ret = -ret; /* positive-ify */
  while (ret != 0) { /* it'll print out backwards */
    char x = '0' + (ret % 10);
    syscall(__NR_write, 2, &x, 1);
    ret /= 10;
  }
  syscall(__NR_write, 2, "\n", 1);
  trap();
}
static void die(char *msg) {
  syscall(__NR_write, 2, msg, strlen(msg));
  syscall(__NR_write, 2, "\n", 1);
  trap();
}

int fbfd = -1;
static void fb_thread(void) {
  uint fbpage = fbaddr & ~0x0FFF;
  uint real_len = FBLEN + (fbaddr - fbpage);
  if (fbfd < 0) {
    int fd = syscall(__NR_memfd_create, "fb", 0);
    if (fd < 0) { diep("memfd_create", fd); }
    int written = 0;
    while (written < real_len) {
      int ret = syscall(__NR_write, fd, fbpage+written, real_len - written);
      if (ret < 0) { diep("write", ret); }
      written += ret;
    }
    if (!__sync_bool_compare_and_swap(&fbfd, -1, fd)) {
      syscall(__NR_close, fd);
    }
  }
  if (fbfd < 0) { die("fbfd"); }
  int ret;
  ret = syscall(__NR_mmap2, fbpage, real_len,
                PROT_READ|PROT_WRITE, MAP_FIXED|MAP_SHARED, fbfd, 0);
  if (ret != fbpage) { diep("mmap", ret); }
}

static void handle_sigsegv(int sig, siginfo_t *si, void *unused) {
  if ((char*)si->si_addr >= (char*)fbaddr &&
      (char*)si->si_addr < (char*)fbaddr + FBLEN) {
    fb_thread();
  }
}

void steal_frame_buffer(void) {
  fbaddr = qimage_bits(fbimgaddr);

  struct sigaction sa, oldsa;
  sa.sa_flags = SA_SIGINFO;
  for (int i = 0; i < sizeof(sigset_t); ++i) { /* sigsetempty, hopefully */
    *((char*)(&sa.sa_mask)+i) = 0;
  }
  int ret;
  if ((ret = syscall(__NR_sigaction, SIGSEGV, &sa, &oldsa)) < 0) {
    diep("signal", ret);
  }
  if ((ret = syscall(__NR_mprotect, fbaddr & ~0x0FFF, FBLEN + (fbaddr & 0xFFF),
                     PROT_READ)) < 0) { diep("mprotect", ret); }
  fb_thread();
  if ((ret = syscall(__NR_sigaction, SIGSEGV, &oldsa, NULL)) < 0) {
    diep("signal restore", ret);
  }

  socketfd = syscall(__NR_socket, AF_UNIX, SOCK_DGRAM, 0);
  if (socketfd < 0) { diep("socket", socketfd); }
  set_socket_path();
  ret = syscall(__NR_connect, socketfd, (struct sockaddr *)&addr, sizeof(addr));
  if (ret < 0) { diep("connect", ret); }

  /* Avoid R_ARM_ABS32. Why does one show up even with -fpic? */
  uint addr_for_io = fbaddr;
  struct iovec v = {
    .iov_base = &addr_for_io,
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
  struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(sizeof(int));
  *(int*)CMSG_DATA(cmsg) = fbfd;
  ret = syscall(__NR_sendmsg, socketfd, &msg, 0);
  if (ret < 0) { diep("sendmsg", ret); }

  trap();
}

void sendupdate_hook(uint p0, uint p1, uint p2, uint p3) {
  uint params[] = { p0, p1, p2, p3 };
  syscall(__NR_write, socketfd, params, 16);
}
