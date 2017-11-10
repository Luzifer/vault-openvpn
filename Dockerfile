# Usage:
#   docker run --rm -it -e VAULT_ADDR='<URL>:8200' -e VAULT_TOKEN='<TOKEN>' jasongwartz/vault-openvpn <command>
# Example:
#   docker run --rm -it -e VAULT_ADDR='https://myvault.example.com:8200' -e VAULT_TOKEN='fdas-fdasf-fdsa-23t-das' jasongwartz/vault-openvpn --pki-mountpoint vault-pki list
FROM golang:alpine

WORKDIR /go/src/vault-openvpn
COPY . .

RUN apk update && apk add git curl

ENV GOBIN=$GOPATH/bin
RUN go-wrapper download
RUN go-wrapper install

RUN curl https://raw.githubusercontent.com/Luzifer/vault-openvpn/master/example/openvpn-sample/client.conf > client.conf
RUN curl https://raw.githubusercontent.com/Luzifer/vault-openvpn/master/example/openvpn-sample/server.conf > server.conf

ENTRYPOINT ["vault-openvpn"]
