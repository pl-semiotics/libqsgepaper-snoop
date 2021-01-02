{ stdenv, lib, unicorn }:

stdenv.mkDerivation {
  pname = "libqsgepaper-snoop";
  version = "0.0.1";
  src = lib.cleanSource ./.;
  buildInputs = [ unicorn ];
  installPhase = ''
    mkdir -p $out/lib
    cp build/libqsgepaper-snoop.so $out/lib
    cp build/libqsgepaper-snoop-standalone.a $out/lib
    mkdir -p $out/share/libqsgepaper-snoop
    cp build/payload.bin $out/share/libqsgepaper-snoop
    mkdir -p $out/libexec/libqsgepaper-snoop
    cp build/libqsgepaper_extract_info $out/libexec/libqsgepaper-snoop
    mkdir -p $out/include
    cp libqsgepaper-snoop.h $out/include
  '';
}
