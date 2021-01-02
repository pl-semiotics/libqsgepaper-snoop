# Introduction

This library provides damage tracking information version 2 of the
[reMarkable tablet](https://remarkable.com). Unlike the reMarkable 1,
the reMarkable 2 does not use the integrated e-paper display
controller on the SoC used for the system, but instead drives the
display directly from software. This makes it impossible to extract
damage information from the (nonexistent) hardware driver, which was
the approach taken on the rM1.

It is therefore necessary to inject code into the process that _is_
controlling the framebuffer in order to provide notification of damage
update. In all known production software, the display is controlled by
executables using the proprietary static library `libqsgepaper.a`. The
purpose of this project, therefore, is to inject code into a
`libqsgepaper.a`-based binary that exports the software framebuffer to
which content is drawn, as well as damage notifications whenever an
update is sent to the display.

In order to work on as wide a range of driving binaries as possible,
this library avoids using hardcoded addresses or similar techniques.
Instead, it uses data taken from Qt metaobjects that are part of the
interface of `libqsgepaper.a` in order to locate relevant functions
and data.

It is relatively easy to find the Qt metaobject in the data section of
the binary@riving the display. Unfortunately, this does not give
direct access to the virtual framebuffer, or to the function used to
notify the display that an update is present. In order to find these
things, the [Unicorn Engine](https://www.unicorn-engine.org/) emulator
is used to emulate the Qt static meta-call function (when given
appropriate parameters). This uses the fact that `libqsgepaper.a`
passes the framebuffer address to `QImage::fill` in the (inlined)
`clearScreen` function, the fact that `sendUpdate` is not inlined into
`QObject::metacall`, and little else.

Once the appropriate addresses have been found, a writable and
executable page is `mmap`d via ptrace()ing the target process, and a
payload built from [payload-c.c](./payload-c.c) and
[payload-a.s](./payload-a.s) is injected. The preamble of the
`sendUpdate` function in the original process is overwritten to
redirect to a portion of the payload which saves the information
damaged, runs the original `sendUpdate`,and then exports the damage
information over a Unix domain socket. The payload also includes
initialization code that replaces the private anonymous mapping of the
framebuffer with a shared mapping backed by an in-memory file from
`memfd_create` and connects to a Unix domain socket opened by the
process requesting the information.

The necessary addresses appear to in practice remain stable over
multiple executions of the same binary, as the `EPFramebuffer` class
which is being hooked into is a singleton and address-space layout
randomization is not used on the reMarkable. Therefore, in order to
improve startup time and minimize resource usage, the Unicorn-based
emulation analysis is not run every time, but rather stored in a
cache.

# Building

The supported way to build this is via the
[Nix](https://nixos.org/nix) package manager, through the
[nix-remarkable](https://github.com/peter-sa/nix-remarkable)
expressions. To build just this project via `nix build` from this
repo, download it into the `pkgs/` directory of `nix-remarkable`.

For other systems, the [Makefile](./Makefile) provides the necessary
commands. A suitable build of the Unicorn engine (static for the
standalone static library) is required.

Prebuilt binaries are available in the [Releases
tab](https://github.com/pl-semiotics/libqsgepaper-snoop/releases).

# Usage

See [libqsgepaper-snoop.h](./libqsgepaper-snoop.h).
