FROM	docker.io/library/golang AS builder

WORKDIR	/go/src/xhash
COPY	. .

RUN	go install github.com/klauspost/cpuid/v2/cmd/cpuid@v2.3.0
RUN	make CGO_ENABLED=0

FROM	scratch
COPY	--from=builder /go/src/xhash/xhash /usr/local/bin/xhash

ENTRYPOINT ["/usr/local/bin/xhash"]
