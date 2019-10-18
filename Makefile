all:
	@go get
	@go build

install: xhash
	@install -m 0755 xhash /usr/local/bin
