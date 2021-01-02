#ifndef CACHED_INFO_H_
#define CACHED_INFO_H_

#include <sys/types.h>

#include "private.h"

#define HEADER_MAGIC "libqsgepaper-snoop cached info v1\n"
#define SIZE_BYTE sizeof(HEADER_MAGIC)
#define STATE_BEGIN sizeof(HEADER_MAGIC) + sizeof(uint);

struct check_bit {
  uint addr;
  uint eval;
};
struct cached_state {
  uint qimage_bits_addr_addr;
  uint mmap_addr_addr;
  uint fb_addr;
  uint sendUpdate_addr;
  /* the user code could use this directly, but really it's used for
   * checking that nothing's changed. however, since we might have
   * injected already, it doesn't go in cbits below.
   */
  uint su_preamble[N_PREAMBLE_INSTRS];
  /* for verification that this is the correct executable only */
  uint ncbits;
  struct check_bit cbits[];
};

#endif /* CACHED_INFO_H_ */
