FROM	golang as builder

WORKDIR	/go/src/xhash
COPY	. .

RUN	make

FROM	scratch
COPY	--from=builder /go/src/xhash/xhash /usr/local/bin/xhash

ENTRYPOINT ["/usr/local/bin/xhash"]
