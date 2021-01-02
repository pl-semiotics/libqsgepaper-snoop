SECTIONS
{
  .extract_info : {
    extract_info_begin = . ;
    build/libqsgepaper_extract_info.bin(.data)
    extract_info_end = . ;
  }
  .payload : {
    injectable_begin = . ;
    build/payload.o(.binary)
    injectable_end = . ;
  }
}
