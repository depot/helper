FROM golang:1.20 AS go-builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -x -v -o /srv

FROM alpine:3 AS socat-builder

RUN apk --update add build-base bash automake git curl linux-headers

WORKDIR /src
RUN curl -LO http://www.dest-unreach.org/socat/download/socat-1.7.4.4.tar.gz && \
    tar xzvf socat-1.7.4.4.tar.gz && \
    cd socat-1.7.4.4 && \
    CC='/usr/bin/gcc -static' CFLAGS='-fPIC' ./configure --disable-help --disable-stdio --disable-fdnum --disable-file --disable-creat --disable-gopen --disable-pipe --disable-termios --disable-unix --disable-abstract-unixsocket --disable-rawip --disable-genericsocket --disable-udp --disable-sctp --disable-vsock --disable-socks4 --disable-socks4a --disable-proxy --disable-system --disable-pty --disable-fs --disable-readline --disable-openssl --disable-tun --disable-sycls --disable-filan --disable-libwrap && \
    make && \
    strip socat

FROM scratch AS release-stage
COPY --from=go-builder /srv /srv
COPY --from=socat-builder /src/socat-1.7.4.4/socat /usr/bin/socat
CMD ["/srv/helper"]
