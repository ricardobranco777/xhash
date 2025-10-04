FROM	docker.io/library/golang AS builder

WORKDIR	/go/src/xhash
COPY	. .

RUN	make CGO_ENABLED=0

FROM	scratch
COPY	--from=builder /go/src/xhash/xhash /usr/local/bin/xhash

ENTRYPOINT ["/usr/local/bin/xhash"]
