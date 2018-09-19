SSL_LIB_DIR = $(shell ls -d /usr/local/ssl/lib64 2>/dev/null)
ifeq ($(SSL_LIB_DIR),)
	SSL_LIB_DIR := /usr/local/ssl/lib
endif

.PHONY: all

all:
	go build -ldflags "-L /usr/local/ssl/lib -extldflags \"-Wl,-rpath=${SSL_LIB_DIR} -static -ldl\""

install: xhash
	@install -m 0755 xhash /usr/local/bin
