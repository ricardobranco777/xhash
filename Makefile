BIN	= xhash

all:	$(BIN)

$(BIN): *.go
	@CGO_ENABLED=0 go build

test:
	@go vet
	@go test -v

clean:
	@go clean

gen:
	@rm -f go.mod go.sum
	@go mod init $(BIN)
	@go mod tidy

install:
	@install -s -m 0755 $(BIN) /usr/local/bin/ 2>/dev/null
