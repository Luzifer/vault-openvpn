package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/Luzifer/rconfig"
	log "github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/olekukonko/tablewriter"
)

const (
	actionList             = "list"
	actionMakeClientConfig = "client"
	actionMakeServerConfig = "server"
	actionRevoke           = "revoke"

	dateFormat = "2006-01-02 15:04:05 -0700"
)

var (
	cfg = struct {
		VaultAddress string `flag:"vault-addr" env:"VAULT_ADDR" default:"https://127.0.0.1:8200" description:"Vault API address"`
		VaultToken   string `flag:"vault-token" env:"VAULT_TOKEN" vardefault:"vault-token" description:"Specify a token to use instead of app-id auth"`

		PKIMountPoint string `flag:"pki-mountpoint" default:"/pki" description:"Path the PKI provider is mounted to"`
		PKIRole       string `flag:"pki-role" default:"openvpn" description:"Role defined in the PKI usable by the token and able to write the specified FQDN"`

		AutoRevoke bool          `flag:"auto-revoke" default:"false" description:"Automatically revoke older certificates for this FQDN"`
		CertTTL    time.Duration `flag:"ttl" default:"8760h" description:"Set the TTL for this certificate"`

		LogLevel       string `flag:"log-level" default:"info" description:"Log level to use (debug, info, warning, error)"`
		VersionAndExit bool   `flag:"version" default:"false" description:"Prints current version and exits"`
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

	if logLevel, err := log.ParseLevel(cfg.LogLevel); err == nil {
		log.SetLevel(logLevel)
	} else {
		log.Fatalf("Unable to interprete log level: %s", err)
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
	if len(rconfig.Args()) < 2 {
		fmt.Println("Usage: vault-openvpn [options] <action> <FQDN>")
		fmt.Println("         actions: client / server / list / revoke")
		os.Exit(1)
	}

	action := rconfig.Args()[1]
	fqdn := ""
	if len(rconfig.Args()) == 3 {
		fqdn = rconfig.Args()[2]
	}

	var err error

	clientConfig := api.DefaultConfig()
	clientConfig.ReadEnvironment()
	clientConfig.Address = cfg.VaultAddress

	client, err = api.NewClient(clientConfig)
	if err != nil {
		log.Fatalf("Could not create Vault client: %s", err)
	}

	client.SetToken(cfg.VaultToken)

	switch action {
	case actionRevoke:
		if err := revokeOlderCertificate(fqdn); err != nil {
			log.Fatalf("Could not revoke certificate: %s", err)
		}
	case actionMakeClientConfig:
		if err := generateCertificateConfig("client.conf", fqdn); err != nil {
			log.Fatalf("Unable to generate config file: %s", err)
		}
	case actionMakeServerConfig:
		if err := generateCertificateConfig("server.conf", fqdn); err != nil {
			log.Fatalf("Unable to generate config file: %s", err)
		}
	case actionList:
		if err := listCertificates(); err != nil {
			log.Fatalf("Unable to list certificates: %s", err)
		}

	default:
		log.Fatalf("Unknown action: %s", action)
	}
}

func listCertificates() error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"FQDN", "Not Before", "Not After", "Serial"})
	table.SetBorder(false)

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

		cert, err := parseCertificate(cs.Data["certificate"].(string))
		if err != nil {
			return err
		}

		if revokationTime, ok := cs.Data["revocation_time"]; ok {
			rt, err := revokationTime.(json.Number).Int64()
			if err == nil && rt < time.Now().Unix() && rt > 0 {
				// Don't display revoked certs
				continue
			}
		}

		table.Append([]string{
			cert.Subject.CommonName,
			cert.NotBefore.Format(dateFormat),
			cert.NotAfter.Format(dateFormat),
			serial.(string),
		})
	}

	table.Render()
	return nil
}

func generateCertificateConfig(tplName, fqdn string) error {
	if cfg.AutoRevoke {
		if err := revokeOlderCertificate(fqdn); err != nil {
			return fmt.Errorf("Could not revoke certificate: %s", err)
		}
	}

	caCert, err := getCACert()
	if err != nil {
		return fmt.Errorf("Could not load CA certificate: %s", err)
	}

	tplv, err := generateCertificate(fqdn)
	if err != nil {
		return fmt.Errorf("Could not generate new certificate: %s", err)
	}

	tplv.CertAuthority = caCert

	if err := renderTemplate(tplName, tplv); err != nil {
		return fmt.Errorf("Could not render configuration: %s", err)
	}

	return nil
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

		if revokationTime, ok := cs.Data["revocation_time"]; ok {
			rt, err := revokationTime.(json.Number).Int64()
			if err == nil && rt < time.Now().Unix() && rt > 0 {
				log.WithFields(log.Fields{
					"cn": cn,
				}).Debug("Found revoked certificate")
				continue
			}
		}

		log.WithFields(log.Fields{
			"cn":     cn,
			"serial": serial,
		}).Info("Found valid certificate")

		if cn == fqdn {
			path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "revoke"}, "/")
			if _, err := client.Logical().Write(path, map[string]interface{}{
				"serial_number": serial.(string),
			}); err != nil {
				return errors.New("Revoke of serial " + serial.(string) + " failed: " + err.Error())
			}
			log.WithFields(log.Fields{
				"cn":     cn,
				"serial": serial,
			}).Info("Revoked certificate")
		}
	}

	return nil
}

func parseCertificate(pemString string) (*x509.Certificate, error) {
	data, _ := pem.Decode([]byte(pemString))
	return x509.ParseCertificate(data.Bytes)
}

func commonNameFromCertificate(pemString string) (string, error) {
	cert, err := parseCertificate(pemString)
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

	log.WithFields(log.Fields{
		"cn":     fqdn,
		"serial": secret.Data["serial_number"].(string),
	}).Info("Generated new certificate")

	return &templateVars{
		Certificate: secret.Data["certificate"].(string),
		PrivateKey:  secret.Data["private_key"].(string),
	}, nil
}
