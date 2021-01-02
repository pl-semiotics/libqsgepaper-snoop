CC ?= arm-remarkable-linux-gnueabi-gcc
LD ?= arm-remarkable-linux-gnueabi-ld
AR ?= arm-remarkable-linux-gnueabi-ar
OBJCOPY ?= arm-remarkable-linux-gnueabi-objcopy

.PHONY: all clean

all: build/libqsgepaper_extract_info
all: build/payload.bin
all: build/libqsgepaper-snoop.so build/libqsgepaper-snoop-standalone.a
clean:
	rm -rf build

build:
	mkdir -p build
build/%.o: %.c | build
	$(CC) $(CFLAGS) -c $< -o $@ $(LDFLAGS)
build/%.o: %.s | build
	$(CC) $(ASFLAGS) -c $< -o $@ $(LDFLAGS)
build/%.a: | build
	$(AR) cr $@ $^
build/%.so: | build
	$(CC) -shared -z defs -o $@ $^ $(LDFLAGS)
build/%.xz: build/% | build
	xz -f -k $<

build/extract_info.o: cached_info.h
build/libqsgepaper_extract_info: build/extract_info.o | build
	$(CC) $< -o $@ -Wl,--start-group -lunicorn -larm-softmmu -Wl,--end-group -lpthread
build/libqsgepaper_extract_info.bin: build/libqsgepaper_extract_info.xz
	$(OBJCOPY) -I binary -O elf32-littlearm -B arm $< $@

build/payload-a.o: private ASFLAGS=-ffreestanding
build/payload-c.o: private CFLAGS=-ffreestanding -fno-stack-protector -fPIE -fno-plt -mpic-data-is-text-relative
build/payload.o: build/payload-a.o build/payload-c.o payload.ld | build
	$(LD) -Tpayload.ld -s build/payload-c.o build/payload-a.o -o $@
build/payload.bin: build/payload.o
	$(OBJCOPY) -O binary -j .binary $< $@

build/inject.o: cached_info.h
build/inject-standalone.o: build/inject.o inject-standalone.ld build/libqsgepaper_extract_info.bin build/payload.o | build
	$(LD) -Tinject-standalone.ld -i -o $@ build/inject.o

build/libqsgepaper-snoop-standalone.a: build/inject-standalone.o

build/libqsgepaper-snoop.so: build/inject.o
build/libqsgepaper-snoop.so: private override LDFLAGS += -lcrypto -llzma
