FROM	debian:sid as builder

RUN	apt-get update \
	&& apt-get upgrade -y \
	&& apt-get install --no-install-recommends -y ca-certificates \
		gcc \
		git \
		libc6-dev \
		libssl-dev \
		make \
		wget

RUN	wget -qO- https://storage.googleapis.com/golang/go1.11.1.linux-amd64.tar.gz | tar zxf - -C /tmp/

RUN	PATH=$PATH:/tmp/go/bin GOPATH=/tmp/ go get github.com/ricardobranco777/xhash

# We can safely ignore the warnings here
RUN	cd /tmp/src/github.com/ricardobranco777/xhash/ \
	&& PATH=$PATH:/tmp/go/bin GOPATH=/tmp/ make \
	&& mv xhash /usr/local/bin/

FROM	debian:sid
COPY --from=builder /usr/local/bin/xhash /usr/local/bin

ENTRYPOINT ["/usr/local/bin/xhash"]
