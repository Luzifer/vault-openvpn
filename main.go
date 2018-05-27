package main

import "github.com/Luzifer/vault-openvpn/cmd"

var version = "dev"

func main() {
	cmd.Execute(version)
}
