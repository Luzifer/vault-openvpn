package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/Luzifer/go_helpers/str"
	"github.com/Luzifer/rconfig"
	"github.com/hashicorp/go-rootcerts"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
)

const (
	actionRevoke           = "revoke"
	actionMakeClientConfig = "client"
	actionMakeServerConfig = "server"
)

var (
	cfg = struct {
		VaultAddress string `flag:"vault-addr" env:"VAULT_ADDR" default:"https://127.0.0.1:8200" description:"Vault API address"`
		VaultToken   string `flag:"vault-token" env:"VAULT_TOKEN" vardefault:"vault-token" description:"Specify a token to use instead of app-id auth"`

		PKIMountPoint string `flag:"pki-mountpoint" default:"/pki" description:"Path the PKI provider is mounted to"`
		PKIRole       string `flag:"pki-role" default:"openvpn" description:"Role defined in the PKI usable by the token and able to write the specified FQDN"`

		AutoRevoke bool          `flag:"auto-revoke" default:"false" description:"Automatically revoke older certificates for this FQDN"`
		CertTTL    time.Duration `flag:"ttl" default:"8760h" description:"Set the TTL for this certificate"`

		VersionAndExit bool `flag:"version" default:"false" description:"Prints current version and exits"`
	}{}

	version = "dev"

	client *api.Client
)

type templateVars struct {
	CertAuthority string
	Certificate   string
	PrivateKey    string
}

func vaultTokenFromDisk() string {
	vf, err := homedir.Expand("~/.vault-token")
	if err != nil {
		return ""
	}

	data, err := ioutil.ReadFile(vf)
	if err != nil {
		return ""
	}

	return string(data)
}

func init() {
	rconfig.SetVariableDefaults(map[string]string{
		"vault-token": vaultTokenFromDisk(),
	})

	if err := rconfig.Parse(&cfg); err != nil {
		log.Fatalf("Unable to parse commandline options: %s", err)
	}

	if cfg.VersionAndExit {
		fmt.Printf("vault-openvpn %s\n", version)
		os.Exit(0)
	}

	if cfg.VaultToken == "" {
		log.Fatalf("[ERR] You need to set vault-token")
	}
}

func main() {
	if len(rconfig.Args()) != 3 {
		fmt.Println("Usage: vault-openvpn [options] <action> <FQDN>")
		fmt.Println("         actions: client / server / revoke")
		os.Exit(1)
	}

	action := rconfig.Args()[1]
	fqdn := rconfig.Args()[2]

	if !str.StringInSlice(action, []string{actionRevoke, actionMakeClientConfig, actionMakeServerConfig}) {
		log.Fatalf("Unknown action: %s", action)
	}

	var err error

	clientConfig := api.DefaultConfig()
	clientConfig.Address = cfg.VaultAddress

	tlsConfig := clientConfig.HttpClient.Transport.(*http.Transport).TLSClientConfig
	err = rootcerts.ConfigureTLS(tlsConfig, nil)
	if err != nil {
		log.Fatalf("Could not configure TLS: %s", err)
	}

	client, err = api.NewClient(clientConfig)
	if err != nil {
		log.Fatalf("Could not create Vault client: %s", err)
	}

	client.SetToken(cfg.VaultToken)

	if cfg.AutoRevoke || action == actionRevoke {
		if err := revokeOlderCertificate(fqdn); err != nil {
			log.Fatalf("Could not revoke certificate: %s", err)
		}
	}

	if action != actionMakeClientConfig && action != actionMakeServerConfig {
		return
	}

	tplName := "client.conf"
	if action == actionMakeServerConfig {
		tplName = "server.conf"
	}

	caCert, err := getCACert()
	if err != nil {
		log.Fatalf("Could not load CA certificate: %s", err)
	}

	tplv, err := generateCertificate(fqdn)
	if err != nil {
		log.Fatalf("Could not generate new certificate: %s", err)
	}

	tplv.CertAuthority = caCert

	if err := renderTemplate(tplName, tplv); err != nil {
		log.Fatalf("Could not render configuration: %s", err)
	}
}

func renderTemplate(tplName string, tplv *templateVars) error {
	raw, err := ioutil.ReadFile(tplName)
	if err != nil {
		return err
	}

	tpl, err := template.New("tpl").Parse(string(raw))
	if err != nil {
		return err
	}

	return tpl.Execute(os.Stdout, tplv)
}

func revokeOlderCertificate(fqdn string) error {
	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "certs"}, "/")
	secret, err := client.Logical().List(path)
	if err != nil {
		return err
	}

	if secret.Data == nil {
		return errors.New("Got no data from backend")
	}

	for _, serial := range secret.Data["keys"].([]interface{}) {
		path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "cert", serial.(string)}, "/")
		cs, err := client.Logical().Read(path)
		if err != nil {
			return errors.New("Unable to read certificate: " + err.Error())
		}

		cn, err := commonNameFromCertificate(cs.Data["certificate"].(string))
		if err != nil {
			return err
		}

		log.Printf("Found certificate %s with CN %s", serial, cn)

		if cn == fqdn {
			path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "revoke"}, "/")
			if _, err := client.Logical().Write(path, map[string]interface{}{
				"serial_number": serial.(string),
			}); err != nil {
				return errors.New("Revoke of serial " + serial.(string) + " failed: " + err.Error())
			}
			log.Printf("Revoked certificate %s", serial)
		}
	}

	return nil
}

func commonNameFromCertificate(pemString string) (string, error) {
	data, _ := pem.Decode([]byte(pemString))
	cert, err := x509.ParseCertificate(data.Bytes)
	if err != nil {
		return "", err
	}

	return cert.Subject.CommonName, nil
}

func getCACert() (string, error) {
	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "cert", "ca"}, "/")
	cs, err := client.Logical().Read(path)
	if err != nil {
		return "", errors.New("Unable to read certificate: " + err.Error())
	}

	return cs.Data["certificate"].(string), nil
}

func generateCertificate(fqdn string) (*templateVars, error) {
	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "issue", cfg.PKIRole}, "/")
	secret, err := client.Logical().Write(path, map[string]interface{}{
		"common_name": fqdn,
		"ttl":         cfg.CertTTL.String(),
	})

	if err != nil {
		return nil, err
	}

	if secret.Data == nil {
		return nil, errors.New("Got no data from backend")
	}

	return &templateVars{
		Certificate: secret.Data["certificate"].(string),
		PrivateKey:  secret.Data["private_key"].(string),
	}, nil
}
