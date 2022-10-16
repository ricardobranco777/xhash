BIN	= xhash

# Optionally create these hard-links
hash	= b2sum md5sum sha1sum sha224sum sha256sum sha384sum sha512sum
hashsum	= b2 md5 sha1 sha224 sha256 sha384 sha512
ALL	= $(hashsum) $(hash)

all:	$(BIN)

$(BIN): *.go
	@CGO_ENABLED=0 go build

test:
	@go vet
	@go test -v

bench:
	@go test -bench=.

clean:
	@go clean
	@rm -f $(ALL)

gen:
	@rm -f go.mod go.sum
	@go mod init $(BIN)
	@go mod tidy

euid	= $(shell id -u)
ifeq ($(euid),0)
BINDIR	= /usr/local/bin
else
BINDIR	= $(HOME)/bin
endif

install: $(BIN)
	@install -s -m 0755 $(BIN) $(BINDIR)

uninstall:
	@rm -f $(BINDIR)/$(BIN)

$(ALL):	$(BIN)
	@for f in $(ALL) ; do ln -f $(BIN) $$f ; done

ALL:	$(ALL)

install-all: $(ALL)
	@for f in $(ALL) ; do install -m 0755 $$f $(BINDIR) ; done

uninstall-all:
	@for f in $(ALL) ; do rm -vf $(BINDIR)/$$f ; done
