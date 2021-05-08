FROM golang:alpine as builder

COPY . /go/src/github.com/Luzifer/vault-openvpn
WORKDIR /go/src/github.com/Luzifer/vault-openvpn

RUN set -ex \
 && apk add --update git \
 && go install \
      -ldflags "-X main.version=$(git describe --tags --always || echo dev)" \
      -mod=readonly

FROM alpine:latest

LABEL maintainer "Knut Ahlers <knut@ahlers.me>"

RUN set -ex \
 && apk --no-cache add \
      ca-certificates

COPY --from=builder /go/bin/vault-openvpn /usr/local/bin/vault-openvpn
COPY --from=builder /go/src/github.com/Luzifer/vault-openvpn/example/openvpn-sample /usr/local/share/vault-openvpn

WORKDIR /usr/local/share/vault-openvpn

ENTRYPOINT ["/usr/local/bin/vault-openvpn"]
CMD ["--"]

# vim: set ft=Dockerfile:
