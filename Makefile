
WIRESHARK_CFLAGS=$(shell pkg-config wireshark --cflags)
WIRESHARK_LIBS=$(shell pkg-config wireshark --cflags --libs)

CFLAGS=$(WIRESHARK_CFLAGS) -Wall -Werror -O2 -std=gnu99 -fPIC
LDFLAGS=$(WIRESHARK_LIBS) -Wl,--no-undefined

WIRESHARK_VER=4.0
WIRESHARK_PUGINS=~/.local/lib/wireshark/plugins/$(WIRESHARK_VER)/epan

OUTFILE=build/bld.so

all: $(OUTFILE)

clean:
	rm -rf build

.PHONY: clean

$(OUTFILE): src/ws-bld.c src/bld-proto.h
	@mkdir -p build
	$(CC) -shared -o $@ $(CFLAGS) src/ws-bld.c $(LDFLAGS)

install: $(OUTFILE)
	cp -fv $(OUTFILE) $(WIRESHARK_PUGINS)/bld.so
