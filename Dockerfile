FROM golang:alpine

LABEL maintainer "Knut Ahlers <knut@ahlers.me>"

ADD . /go/src/github.com/Luzifer/vault-openvpn
WORKDIR /go/src/github.com/Luzifer/vault-openvpn

RUN set -ex \
 && apk add --update git ca-certificates \
 && go install -ldflags "-X main.version=$(git describe --tags || git rev-parse --short HEAD || echo dev)" \
 && apk del --purge git

WORKDIR /go/src/github.com/Luzifer/vault-openvpn/example/openvpn-sample

ENTRYPOINT ["/go/bin/vault-openvpn"]
CMD ["--"]
