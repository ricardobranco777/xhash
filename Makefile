SSL_LIB_DIR = $(shell ls -d /usr/local/ssl/lib64 2>/dev/null)
ifeq ($(SSL_LIB_DIR),)
	SSL_LIB_DIR := /usr/local/ssl/lib
endif

.PHONY: all

all:
	# We can safely ignore linker warnings. Glibc static linking is broken.
	go build -ldflags "-L ${SSL_LIB_DIR} -extldflags \"-ldl -static\"" || \
	go build -ldflags "-L ${SSL_LIB_DIR} -extldflags \"-Wl,-rpath=${SSL_LIB_DIR}\""

install: xhash
	@install -m 0755 xhash /usr/local/bin
