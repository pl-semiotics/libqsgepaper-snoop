ENTRY(steal_frame_buffer)
SECTIONS
{
  .binary : AT(0) {
    *(.magic)
    *(.asheader)
    *(.cheader0)
    *(.cheader1)
    *(.cheader2)
    *(.cheader3)
    *(.asentry)
    *(.text)
    *(.data)
    *(.rodata)
    *(.rodata*)
    *(.bss)
  }
}
