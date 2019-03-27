BUILDARCH := $(shell go env GOARCH)
HOSTARCH ?= $(BUILDARCH)
TARGETARCH ?= arm64
AFLVER ?= 2.52b

ifeq ("$(TARGETARCH)", "arm64")
	CC ?= "aarch64-linux-gnu-gcc"
	CXX ?= "aarch64-linux-gnu-g++"
else ifeq ("$(TARGETARCH)", "arm")
	CC ?= "arm-linux-gnueabihf-gcc"
	CXX ?= "arm-linux-gnueabihf-g++"
endif

NOSTATIC ?= 0

ifeq ($(NOSTATIC), 0)
	ADDCFLAGS += -static
endif

.PHONY: all fuzzer zip afl-setup afl-fuzz format clean

all: executor fuzzer

executor:bin/$(TARGETARCH)/executor

bin/$(TARGETARCH)/executor: executor/executor.cc
	mkdir -p ./bin/$(TARGETARCH)
	$(CXX) -o $@ $^ \
		-Wall -Wparentheses -Werror \
		$(ADDCFLAGS) $(CFLAGS)

fuzzer: afl-setup afl-fuzz afl-cmin afl-showmap

afl-setup: fuzzer/afl-$(AFLVER)

fuzzer/afl-$(AFLVER):
	cd fuzzer; \
	wget lcamtuf.coredump.cx/afl/releases/afl-$(AFLVER).tgz; \
	tar -xf afl-$(AFLVER).tgz; \
	rm afl-$(AFLVER).tgz; \
	cd afl-$(AFLVER); \
	patch -p1 < ../afl-$(AFLVER).patch

afl-cmin: bin/$(TARGETARCH)/afl-cmin

bin/$(TARGETARCH)/fuzzer:
	mkdir -p ./bin/$(TARGETARCH)
	$(MAKE) AFL_NO_X86=1 ADDCFLAGS="$(ADDCFLAGS)" CC=$(CC) -C fuzzer/afl-$(AFLVER) afl-fuzz \
		&& mv fuzzer/afl-$(AFLVER)/afl-fuzz $@

afl-fuzz: bin/$(TARGETARCH)/fuzzer

bin/$(TARGETARCH)/afl-cmin:
	mkdir -p ./bin/$(TARGETARCH)
	cp fuzzer/afl-$(AFLVER)/afl-cmin $@

afl-showmap: bin/$(TARGETARCH)/afl-showmap

bin/$(TARGETARCH)/afl-showmap:
	mkdir -p ./bin/$(TARGETARCH)
	$(MAKE) AFL_NO_X86=1 ADDCFLAGS="$(ADDCFLAGS)" CC=$(CC) -C fuzzer/afl-$(AFLVER) afl-showmap \
		&& mv fuzzer/afl-$(AFLVER)/afl-showmap $@

zip: bin.zip

bin.zip:
	zip -r $@ bin

format:
	clang-format -i executor/executor.cc fuzzer/ashmem.h
	find linux -iname '*.c' -o -iname '*.h' | xargs clang-format -i

clean:
	rm -rf ./bin ./fuzzer/afl-$(AFLVER)
