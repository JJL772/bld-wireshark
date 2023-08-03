
# Wireshark BLD

This repo contains the source code for a Wireshark packet dissector for SLAC's BLD protocol.

## Prerequisites

To compile the plugin, you'll need a C compiler with at least C99 support, make, pkg-config and wireshark.

Some distributions (such as Debian) package Wireshark development libraries and headers
separately from the main application. Make sure to install your distribution's wireshark
development package (i.e. `wireshark-dev` on Debian and its derivatives).


## Compiling & Installing

Simply run `make` to compile:
```sh
make
```

For Wireshark version 2.6.0 and later, `WIRESHARK_VER` must be set accordingly. For example, installing a plugin for Wireshark 4.0.7 would be done
as follows:
```sh
make install WIRESHARK_VER=4.0
```

For Wireshark versions before 2.6.0:
```sh
make install WIRESHARK_PUGINS=~/.wireshark/plugins
```

You may verify the dissector is properly installed by launching Wireshark, navigating to the toolbar > Help > About > Plugins and looking
for bld.so in the list.
