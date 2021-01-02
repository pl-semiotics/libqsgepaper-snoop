#define _GNU_SOURCE
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <elf.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <string.h>
#include <signal.h>
#include <libgen.h>
#include <sys/wait.h>

#include <unicorn/unicorn.h>

#include "cached_info.h"

#define MO_METACALL_OFF 4*3

/*****************************
 * UTILITIES/DATA STRUCTURES *
 *****************************/
static void diep(char *words) {
  perror(words);
  exit(1);
}

static void die(const char* format, ...) {
  va_list args;
  va_start(args, format);
  vfprintf(stderr, format, args);
  va_end(args);
  exit(1);
}

/* a metaobject candidate, in a linked list of such */
struct mo_cand {
  uint mo_addr;
  int clearScreen_num;
  int sendUpdate_num;
  struct mo_cand *next;
};
/* the information we can get from the exe */
struct exe_info {
  struct mo_cand *mo;
  uint qimage_fill_addr_addr;
  uint qimage_bits_addr_addr;
  uint mmap_addr_addr;
};
/* that plus the stuff we pull out of a process */
struct dyn_info {
  pid_t pid;
  const struct exe_info *static_info;
  uc_engine *uc;
  uint metacall_addr;
  uint qimage_fill_addr;
  uint fb_addr;
  uint sendUpdate_addr;
  uint su_preamble[N_PREAMBLE_INSTRS];
};

/*******************
 * STATIC ANALYSIS *
 *******************/
#define SHDR(n) ((Elf32_Shdr *)(x+hdr->e_shoff+n*hdr->e_shentsize))
#define NSHDR (hdr->e_shnum ? hdr->e_shnum : SHDR(0)->sh_size)
#define SKIP_RESERVED_SECTIONS(i) if (i == 0 || (i >= SHN_LORESERVE && i <= SHN_HIRESERVE)) { continue; }
#define ELF_MAGIC {0x7f,'E','L','F',ELFCLASS32,ELFDATA2LSB,EV_CURRENT,ELFOSABI_LINUX}
#define QSMOA_MANGLED "_ZN7QObject16staticMetaObjectE"
#define QIF_MANGLED "_ZN6QImage4fillEN2Qt11GlobalColorE"
#define QIB_MANGLED "_ZN6QImage4bitsEv"

#define NOT_FOUND ((uint)-1)
static Elf32_Shdr *find_section(char *x, Elf32_Ehdr *hdr, uint addr) {
  for (int k = 0; k < NSHDR; k++) {
    SKIP_RESERVED_SECTIONS(k)
    Elf32_Shdr *s = SHDR(k);
    if (s->sh_type == SHT_NOBITS) { continue; }
    if (s->sh_addr <= addr && s->sh_addr + s->sh_size > addr) {
      return s;
    }
  }
  return NULL;
}
static int addr_to_off_s(char *x, Elf32_Shdr *s, uint addr) {
  if (!s) { return NOT_FOUND; }
  if (s->sh_addr <= addr && s->sh_addr + s->sh_size > addr) {
    return addr-s->sh_addr+s->sh_offset;
  }
  return NOT_FOUND;
}
static int addr_to_off(char *x, Elf32_Ehdr *hdr, uint addr) {
  return addr_to_off_s(x, find_section(x, hdr, addr), addr);
}
static int invalid_off(char *x, Elf32_Shdr *s, uint off) {
  return !(s && s->sh_offset <= off && s->sh_offset + s->sh_size > off);
}
static uint off_to_addr(char *x, Elf32_Ehdr *hdr, uint off) {
  for (int k = 0; k < NSHDR; k++) {
    SKIP_RESERVED_SECTIONS(k)
    Elf32_Shdr *s = SHDR(k);
    if (s->sh_type == SHT_NOBITS) { continue; }
    if (s->sh_offset <= off && s->sh_offset + s->sh_size > off) {
      return off-s->sh_offset+s->sh_addr;
    }
  }
  return NOT_FOUND;
}

static struct mo_cand *search_for_epfb(char *x, Elf32_Ehdr *hdr,
                                       size_t size, int qtsmoa,
                                       struct mo_cand *cands) {
  for (uint i = 0; i < size-16; i += 4) {
    if (qtsmoa == *(uint*)(x+i)) {
      Elf32_Shdr *sm = find_section(x, hdr, *(uint*)(x+i+8));
      uint m = addr_to_off_s(x, sm, *(uint*)(x+i+8));
      if (m == NOT_FOUND || invalid_off(x, sm, m+4)) { continue; }
      uint cn = *(uint*)(x+m+4);
      Elf32_Shdr *ss = find_section(x, hdr, *(uint*)(x+i+4));
      uint st = addr_to_off_s(x, ss, *(uint*)(x+i+4)+16*cn+12);
      if (st == NOT_FOUND) { continue; }
      if (invalid_off(x, ss, st-12+*(uint*)(x+st))) { continue; }
      if (strcmp(x+st-12+*(uint*)(x+st), "EPFramebuffer")) { continue; }

      if (invalid_off(x, sm, m+16) || invalid_off(x, sm, m+20)) { continue; }
      int nmeth = *(uint*)(x+m+16);
      int methoff = *(uint*)(x+m+20);

      int getInstance = -1;
      struct mo_cand *next = malloc(sizeof(struct mo_cand));
      next->mo_addr = off_to_addr(x, hdr, i);
      next->clearScreen_num = -1;
      next->sendUpdate_num = -1;
      next->next = cands;
      if (!next) { diep("memory allocation failed"); }
      for (int j = 0; j < nmeth; j++) {
        if (invalid_off(x, sm, m+methoff*4+j*5*4)) { continue; }
        uint noff = *(uint*)(x+m+methoff*4+j*5*4);
        uint na = addr_to_off_s(x, ss, *(uint*)(x+i+4)+16*noff+12);
        if (invalid_off(x, ss, na)) { continue; }
        if (invalid_off(x, ss, na-12+*(uint*)(x+na))) { continue; }
        if (!strcmp(x+na-12+*(uint*)(x+na), "clearScreen") &&
            next->clearScreen_num < 0) {
          next->clearScreen_num = j;
        }
        if (!strcmp(x+na-12+*(uint*)(x+na), "sendUpdate") &&
            next->sendUpdate_num < 0) {
          next->sendUpdate_num = j;
        }
      }
      if (next->clearScreen_num >= 0 && next->sendUpdate_num >= 0) {
        cands = next;
      } else {
        free(next);
      }
    }
  }
  return cands;
}

static struct exe_info read_exe(char *path) {
  int r;
  if ((r = open(path, O_RDONLY)) < 0) { diep("open"); }
  struct stat stat;
  if (fstat(r, &stat)) { diep("stat"); }
  char *x = mmap(NULL, stat.st_size, PROT_READ, MAP_PRIVATE, r, 0);
  if (x == MAP_FAILED) { diep("mmap"); }
  Elf32_Ehdr *hdr = (Elf32_Ehdr*)x;
  char desired_magic[] = ELF_MAGIC;
  if (strncmp(&desired_magic[0],&hdr->e_ident[0],8)) { die("bad elf\n"); }

  struct exe_info result = {
    .mo = NULL,
    .qimage_fill_addr_addr = -1,
    .qimage_bits_addr_addr = -1,
    .mmap_addr_addr = -1,
  };
  int found = 0;
  for (int i = 0; i < NSHDR; i++) {
    SKIP_RESERVED_SECTIONS(i)
    Elf32_Shdr *s = SHDR(i);
    if (s->sh_type == SHT_DYNSYM) {
      Elf32_Shdr *sstr = SHDR(s->sh_link);
      for (int j = 0; j * s->sh_entsize < s->sh_size; j++) {
        Elf32_Sym *sym = (Elf32_Sym *)(x+s->sh_offset+j*s->sh_entsize);
        if (!strcmp(x+sstr->sh_offset+sym->st_name, QSMOA_MANGLED)) {
          result.mo = search_for_epfb(x, hdr,
                                      stat.st_size, sym->st_value,
                                      result.mo);
        }
      }
    }
    if (s->sh_type == SHT_REL) {
      Elf32_Shdr *ssym = SHDR(s->sh_link);
      Elf32_Shdr *sstr = SHDR(ssym->sh_link);
      for (int j = 0; j * s->sh_entsize < s->sh_size; j++) {
        Elf32_Rel *r = (Elf32_Rel *)(x+s->sh_offset+j*s->sh_entsize);
        Elf32_Sym *sym = (Elf32_Sym *)
            (x+ssym->sh_offset+ELF32_R_SYM(r->r_info)*ssym->sh_entsize);
        if (!strcmp(x+sstr->sh_offset+sym->st_name, "mmap")) {
          result.mmap_addr_addr = r->r_offset;
        }
        if (!strcmp(x+sstr->sh_offset+sym->st_name, QIF_MANGLED)) {
          result.qimage_fill_addr_addr = r->r_offset;
        }
        if (!strcmp(x+sstr->sh_offset+sym->st_name, QIB_MANGLED)) {
          result.qimage_bits_addr_addr = r->r_offset;
        }
      }
    }
  }
  return result;
}

/********************
 * DYNAMIC ANALYSIS *
 ********************/
static void wait_for_stop(pid_t pid, int sig) {
  int status;
  do {
    while (pid != waitpid(pid, &status, 0)) {}
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      die("Framebuffer controlling process %d existed\n", pid);
    }
  } while (!WIFSTOPPED(status) || WSTOPSIG(status) != sig);
}

static void get_addrs(struct dyn_info *info) {
  errno = 0;
  info->metacall_addr = ptrace(PTRACE_PEEKDATA, info->pid,
                               info->static_info->mo->mo_addr+12, 0);
  if (errno) { diep("peek metacall addr"); }
  errno = 0;
  info->qimage_fill_addr = ptrace(PTRACE_PEEKDATA, info->pid,
                                  info->static_info->qimage_fill_addr_addr, 0);
  if (errno) { diep("peek qimage_fill addr"); }
}

static bool uc_map_cb(uc_engine *uc, uc_mem_type type,
               uint64_t address, int size,
               int64_t value, pid_t *pid) {
  /* todo (perhaps): coalescing optimizations */
  uint64_t page_base = address & ~0x0FFF;
  size += address-page_base;
  address = page_base;
  do {
    uc_err r = uc_mem_unmap(uc, address, 4096);
    if (r != UC_ERR_OK && r != UC_ERR_NOMEM) { die("uc_mem_unmap %u\n", r); }
    r = uc_mem_map(uc, address, 4096, UC_PROT_ALL);
    if (r != UC_ERR_OK) { die("uc_mem_map %u\n", r); }
    unsigned long bytes;
    for (int p = address; p < address + 4096; p += 4) {
      errno = 0;
      bytes = ptrace(PTRACE_PEEKDATA, *pid, p, 0);
      if (errno) { diep("peek"); }
      uc_mem_write(uc, p, &bytes, 4);
    }
    size -= 4096; address += 4096;
  } while (size > 0);
  return 1;
}
static void init_uc(struct dyn_info *info) {
  uc_err r;
  r = uc_open(UC_ARCH_ARM, UC_MODE_LITTLE_ENDIAN|UC_MODE_ARM, &info->uc);
  if (r != UC_ERR_OK) { die("uc_open %u\n", r); }
  uc_hook h;
  r = uc_hook_add(info->uc, &h, UC_HOOK_MEM_UNMAPPED,
                  uc_map_cb, &info->pid,
                  0x00000000, 0xFFFFFFFF);
  if (r != UC_ERR_OK) { die("uc hook mem %u\n", r); }
}

static void close_uc(struct dyn_info *info) {
  uc_close(info->uc);
  info->uc = NULL;
}

struct qtmc_arg {
  int nwords;
  uint *words;
};
static void setup_metacall(struct dyn_info *info, int call_index,
                           int this, int argc, struct qtmc_arg *argv) {

  struct user_regs regs;
  if (ptrace(PTRACE_GETREGS, info->pid, NULL, &regs)) { diep("get uc regs"); }

  int len = 1; // for some reason, the generated metacall ignores one
  for (int i = 0; i < argc; ++i) {
    len += argv[i].nwords+1; // +1 for the pointer
  }
  if (len % 2) { len += 1; } // 8-byte sp alignment on ARM

  uc_err r;

  uint sp = regs.uregs[13] - 4*len;
  uc_map_cb(info->uc, UC_ERR_WRITE_UNMAPPED, sp, 4*len, 0, &info->pid);
  uint nextarg = sp + 4*(argc+1);
  for (int i = 0; i < argc; ++i) {
    r = uc_mem_write(info->uc, sp + 4*(i+1), &nextarg, 4);
    if (r != UC_ERR_OK) { die("uc mc write arg ptr %u\n", r); }
    r = uc_mem_write(info->uc, nextarg, argv[i].words, 4*argv[i].nwords);
    if (r != UC_ERR_OK) { die("uc mc write arg %u\n", r); }
    nextarg += 4*argv[i].nwords;
  }

  int zero = 0;
  void *regvals[] = { &this, &zero, &call_index, &sp, &sp };
  int wregs[] = {
    UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
    UC_ARM_REG_R3, UC_ARM_REG_SP
  };
  r = uc_reg_write_batch(info->uc, wregs, regvals, 4);
  if (r != UC_ERR_OK) { die("uc mc write regs %u\n", r); }
}

static void find_fb_address(struct dyn_info *info) {
  setup_metacall(info, info->static_info->mo->clearScreen_num, 0, 0, NULL);

  uc_err r =
      uc_emu_start(info->uc, info->metacall_addr, info->qimage_fill_addr, 0, 0);
  if (r != UC_ERR_OK) { die("uc emu start %u\n", r); }

  r = uc_reg_read(info->uc, UC_ARM_REG_R0, &info->fb_addr);
  if (r != UC_ERR_OK) { die("uc read fb address %u\n", r); }
}

struct fsua_cc_data {
  int found_call;
  uint pc;
  uint magic[5];
};
static void find_sendUpdate_code_callback(
    uc_engine *uc, uint64_t address, uint32_t size, struct fsua_cc_data *d) {
  uint pc;
  uc_err r = uc_reg_read(uc, UC_ARM_REG_PC, &pc);
  if (r != UC_ERR_OK) { die("uc pc read magic %u\n", r); }

  if (!d->found_call) {
    uint nregvals[4];
    void *nregvaladdrs[4] =
        { &nregvals[0], &nregvals[1], &nregvals[2], &nregvals[3] };
    int nregs[4] =
        { UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3 };
    r = uc_reg_read_batch(uc, nregs, nregvaladdrs, 4);
    if (r != UC_ERR_OK) { die("uc reg read magic %u\n", r); }

    uint sp, nreg5;
    r = uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    if (r != UC_ERR_OK) { die("uc read sp %u\n", r); }
    r = uc_mem_read(uc, sp, &nreg5, 4);
    if (r != UC_ERR_OK) { die("uc sp read magic %u\n", r); }

    if (!memcmp(nregvals, d->magic, 4*4) &&
        nreg5 == d->magic[4]) {
      d->found_call = 1;
      r = uc_reg_read(uc, UC_ARM_REG_PC, &pc);
      if (r != UC_ERR_OK) { die("uc pc read magic %u\n", r); }
    }
  } else if (pc != d->pc+4) {
    r = uc_emu_stop(uc);
    if (r != UC_ERR_OK) { die("uc emu stop %u\n", r); }
  }

  d->pc = pc;
}
static uint find_sendUpdate_address(struct dyn_info *info) {
  struct fsua_cc_data cd = {
    .found_call = 0,
    .pc = 0,
    /* randomly chosen magic numbers to identify the correct call insn*/
    .magic = { 0xA08B5335, 0xFCE554AE, 0xF7B8C80F, 0x4730C327, 0x5F370907 },
  };
  uint zero = 0;
  struct qtmc_arg args[] = {
    { .nwords = 4, .words = &cd.magic[1], },
    /* for compatibility with various variants, stick a bunch of extra
     * (valid) pointers to 0 in here */
    { .nwords = 1, .words = &zero, },
    { .nwords = 1, .words = &zero, },
    { .nwords = 1, .words = &zero, },
    { .nwords = 1, .words = &zero, },
  };

  setup_metacall(info, info->static_info->mo->sendUpdate_num,
                 cd.magic[0], 5, args);

  uc_hook h;
  uc_err r = uc_hook_add(info->uc, &h, UC_HOOK_CODE,
                         find_sendUpdate_code_callback, &cd,
                         0x00000000, 0xFFFFFFFF);
  if (r != UC_ERR_OK) { die("uc hook code %u\n", r); }

  r = uc_emu_start(info->uc, info->metacall_addr, 0, 0, 0);
  info->sendUpdate_addr = cd.pc;
}

/* warning: not the same as get_sendUpdate_preamble in inject.c! */
static void get_sendUpdate_preamble(struct dyn_info *info) {
  for (int i = 0; i < N_PREAMBLE_INSTRS; ++i) {
    errno = 0;
    info->su_preamble[i] =
        ptrace(PTRACE_PEEKTEXT, info->pid, info->sendUpdate_addr + 4*i, 0);
    if (errno) { diep("peek su instr"); }
  }
}

static void extract_from_process(struct dyn_info *info) {
  if (ptrace(PTRACE_ATTACH, info->pid, NULL, NULL)) { diep("attach"); }
  wait_for_stop(info->pid, SIGSTOP);

  get_addrs(info);
  init_uc(info);
  find_fb_address(info);
  find_sendUpdate_address(info);
  close_uc(info);
  get_sendUpdate_preamble(info);
}

/**********
 * OUTPUT *
 **********/
static void rmkdir(char *filename) {
  char *n2 = malloc(strlen(filename));
  strcpy(n2, filename);
  char *d = dirname(n2);
  if (faccessat(AT_FDCWD, d, F_OK, AT_EACCESS) != 0) {
    rmkdir(d);
    if (mkdir(d, S_IRWXU) < 0) { diep("mkdir"); };
  }
  free(n2);
}
static void write_all(int fd, void *buf, size_t size) {
  do {
    int n = write(fd, buf, size);
    if (n < 0) {
      if (errno == EINTR) { continue; }
      else { diep("write"); }
    }
    buf += n; size -= n;
  } while (size > 0);
}
#define ncbits_ 1
#define state_size (sizeof(struct cached_state)+ncbits_*sizeof(struct check_bit))
static void write_cache(const struct dyn_info *info, char *filename) {
  char struct_mem[state_size] = {0};
  struct cached_state *state = (struct cached_state *)struct_mem;
  state->qimage_bits_addr_addr = info->static_info->qimage_bits_addr_addr;
  state->mmap_addr_addr = info->static_info->mmap_addr_addr;
  state->fb_addr = info->fb_addr;
  state->sendUpdate_addr = info->sendUpdate_addr;
  for (int i = 0; i < N_PREAMBLE_INSTRS; i++) {
    state->su_preamble[i] = info->su_preamble[i];
  }
  state->ncbits = ncbits_;
  state->cbits[0].addr = info->static_info->mo->mo_addr + MO_METACALL_OFF;
  state->cbits[0].eval = info->metacall_addr;
  rmkdir(filename);
  int out = open(filename, O_WRONLY|O_CREAT, S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
  if (out < 0) { diep("open output"); }
  write_all(out, HEADER_MAGIC, sizeof(HEADER_MAGIC));
  uint size = state_size;
  write_all(out, &size, 4);
  write_all(out, state, state_size);
}

int main(int argc, char *argv[]) {
  pid_t pid = atoi(argv[1]);
  char *exename;
  if (asprintf(&exename, "/proc/%d/exe", pid) < 0) { die("asprintf failed\n"); }
  if (!exename) { die("asprintf\n"); }
  struct exe_info static_info = read_exe(exename);
  struct dyn_info info = {
    .pid = pid,
    .static_info = &static_info,
  };
  extract_from_process(&info);
  write_cache(&info, argv[2]);
  return 0;
}
