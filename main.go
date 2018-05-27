package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"sort"
	"strings"
	"text/template"
	"time"

	yaml "gopkg.in/yaml.v2"

	"github.com/Luzifer/rconfig"
	log "github.com/Sirupsen/logrus"
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/helper/certutil"
	homedir "github.com/mitchellh/go-homedir"
	"github.com/olekukonko/tablewriter"
)

const (
	actionList             = "list"
	actionMakeClientConfig = "client"
	actionMakeServerConfig = "server"
	actionRevoke           = "revoke"
	actionRevokeSerial     = "revoke-serial"

	dateFormat   = "2006-01-02 15:04:05"
	defaultsFile = "~/.config/vault-openvpn.yaml"
)

var (
	cfg = struct {
		VaultAddress string `flag:"vault-addr" env:"VAULT_ADDR" default:"https://127.0.0.1:8200" description:"Vault API address"`
		VaultToken   string `flag:"vault-token" env:"VAULT_TOKEN" vardefault:"vault-token" description:"Specify a token to use instead of app-id auth"`

		PKIMountPoint string `flag:"pki-mountpoint" vardefault:"pki-mountpoint" description:"Path the PKI provider is mounted to"`
		PKIRole       string `flag:"pki-role" vardefault:"pki-role" description:"Role defined in the PKI usable by the token and able to write the specified FQDN"`

		AutoRevoke bool          `flag:"auto-revoke" vardefault:"auto-revoke" description:"Automatically revoke older certificates for this FQDN"`
		CertTTL    time.Duration `flag:"ttl" vardefault:"ttl" description:"Set the TTL for this certificate"`
		OvpnKey    string        `flag:"ovpn-key" vardefault:"secret/ovpn" description:"Specify a secret name that holds an OpenVPN shared key"`

		LogLevel       string `flag:"log-level" vardefault:"log-level" description:"Log level to use (debug, info, warning, error)"`
		Sort           string `flag:"sort" vardefault:"sort" description:"How to sort list output (fqdn, issuedate, expiredate)"`
		TemplatePath   string `flag:"template-path" vardefault:"template-path" description:"Path to read the client.conf / server.conf template from"`
		VersionAndExit bool   `flag:"version" default:"false" description:"Prints current version and exits"`
	}{}

	defaultConfig = map[string]string{
		"pki-mountpoint": "/pki",
		"pki-role":       "openvpn",
		"auto-revoke":    "true",
		"ttl":            "8760h",
		"log-level":      "info",
		"sort":           "fqdn",
		"template-path":  ".",
	}

	version = "dev"

	client *api.Client
)

type templateVars struct {
	CertAuthority string
	Certificate   string
	PrivateKey    string
	TlsAuth       string
}

type listCertificatesTableRow struct {
	FQDN      string
	NotBefore time.Time
	NotAfter  time.Time
	Serial    string
}

func (l listCertificatesTableRow) ToLine() []string {
	return []string{
		l.FQDN,
		l.NotBefore.Format(dateFormat),
		l.NotAfter.Format(dateFormat),
		l.Serial,
	}
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

func defualtsFromDisk() map[string]string {
	res := defaultConfig

	df, err := homedir.Expand(defaultsFile)
	if err != nil {
		return res
	}

	yamlSource, err := ioutil.ReadFile(df)
	if err != nil {
		return res
	}

	if err := yaml.Unmarshal(yamlSource, &res); err != nil {
		log.Errorf("Unable to parse defaults file %q: %s", defaultsFile, err)
	}
	return res
}

func init() {
	defaults := defualtsFromDisk()
	defaults["vault-token"] = vaultTokenFromDisk()
	rconfig.SetVariableDefaults(defaults)

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
		fmt.Println("Usage: vault-openvpn [options] <action>")
		fmt.Println("				client <fqdn>						- Generate certificate and output client config")
		fmt.Println("				server <fqdn>						- Generate certificate and output server config")
		fmt.Println("				list										- List all valid (not expired, not revoked) certificates")
		fmt.Println("				revoke <fqdn>						- Revoke all certificates matching to FQDN")
		fmt.Println("				revoke-serial <serial>	- Revoke certificate by serial number")
		os.Exit(1)
	}

	action := rconfig.Args()[1]

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
		if len(rconfig.Args()) < 3 || !validateFQDN(rconfig.Args()[2]) {
			log.Fatalf("You need to provide a valid FQDN")
		}
		if err := revokeCertificateByFQDN(rconfig.Args()[2]); err != nil {
			log.Fatalf("Could not revoke certificate: %s", err)
		}
	case actionRevokeSerial:
		if len(rconfig.Args()) < 3 || !validateSerial(rconfig.Args()[2]) {
			log.Fatalf("You need to provide a valid serial")
		}
		if err := revokeCertificateBySerial(rconfig.Args()[2]); err != nil {
			log.Fatalf("Could not revoke certificate: %s", err)
		}
	case actionMakeClientConfig:
		if len(rconfig.Args()) < 3 || !validateFQDN(rconfig.Args()[2]) {
			log.Fatalf("You need to provide a valid FQDN")
		}
		if err := generateCertificateConfig("client.conf", rconfig.Args()[2]); err != nil {
			log.Fatalf("Unable to generate config file: %s", err)
		}
	case actionMakeServerConfig:
		if len(rconfig.Args()) < 3 || !validateFQDN(rconfig.Args()[2]) {
			log.Fatalf("You need to provide a valid FQDN")
		}
		if err := generateCertificateConfig("server.conf", rconfig.Args()[2]); err != nil {
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

func validateFQDN(fqdn string) bool {
	// Very basic check: It should be delimited by "." and have at least 2 components
	// Vault will do a more sophisticated check
	return len(strings.Split(fqdn, ".")) > 1
}

func validateSerial(serial string) bool {
	// Also very basic check, also here Vault does the real validation
	return len(strings.Split(serial, ":")) > 1
}

func listCertificates() error {
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{"FQDN", "Not Before", "Not After", "Serial"})
	table.SetBorder(false)

	lines := []listCertificatesTableRow{}

	certs, err := fetchValidCertificatesFromVault()
	if err != nil {
		return err
	}

	for _, cert := range certs {
		lines = append(lines, listCertificatesTableRow{
			FQDN:      cert.Subject.CommonName,
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			Serial:    certutil.GetHexFormatted(cert.SerialNumber.Bytes(), ":"),
		})
	}

	sort.Slice(lines, func(i, j int) bool {
		switch cfg.Sort {
		case "issuedate":
			return lines[i].NotBefore.Before(lines[j].NotBefore)

		case "expiredate":
			return lines[i].NotAfter.Before(lines[j].NotAfter)

		default:
			if lines[i].FQDN == lines[j].FQDN {
				return lines[i].NotBefore.Before(lines[j].NotBefore)
			}
			return lines[i].FQDN < lines[j].FQDN
		}
	})

	for _, line := range lines {
		table.Append(line.ToLine())
	}

	table.Render()
	return nil
}

func generateCertificateConfig(tplName, fqdn string) error {
	if cfg.AutoRevoke {
		if err := revokeCertificateByFQDN(fqdn); err != nil {
			return fmt.Errorf("Could not revoke certificate: %s", err)
		}
	}

	caCert, err := getCAChain()
	if err != nil {
		caCert, err = getCACert()
		if err != nil {
			return fmt.Errorf("Could not load CA certificate: %s", err)
		}
	}

	tplv, err := generateCertificate(fqdn)
	if err != nil {
		return fmt.Errorf("Could not generate new certificate: %s", err)
	}

	tplv.CertAuthority = caCert

	if cfg.OvpnKey != "" {
		tplv.TlsAuth, err = fetchOvpnKey(fqdn)
		if err != nil {
			return fmt.Errorf("Could not fetch TlsAuth key: %s", err)
		}
	}

	if err := renderTemplate(tplName, tplv); err != nil {
		return fmt.Errorf("Could not render configuration: %s", err)
	}

	return nil
}

func renderTemplate(tplName string, tplv *templateVars) error {
	raw, err := ioutil.ReadFile(path.Join(cfg.TemplatePath, tplName))
	if err != nil {
		return err
	}

	tpl, err := template.New("tpl").Parse(string(raw))
	if err != nil {
		return err
	}

	return tpl.Execute(os.Stdout, tplv)
}

func fetchCertificateBySerial(serial string) (*x509.Certificate, bool, error) {
	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "cert", serial}, "/")
	cs, err := client.Logical().Read(path)
	if err != nil {
		return nil, false, fmt.Errorf("Unable to read certificate: %s", err.Error())
	}

	revoked := false
	if revokationTime, ok := cs.Data["revocation_time"]; ok {
		rt, err := revokationTime.(json.Number).Int64()
		if err == nil && rt < time.Now().Unix() && rt > 0 {
			// Don't display revoked certs
			revoked = true
		}
	}

	data, _ := pem.Decode([]byte(cs.Data["certificate"].(string)))
	cert, err := x509.ParseCertificate(data.Bytes)
	return cert, revoked, err
}

func fetchValidCertificatesFromVault() ([]*x509.Certificate, error) {
	res := []*x509.Certificate{}

	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "certs"}, "/")
	secret, err := client.Logical().List(path)
	if err != nil {
		return res, err
	}

	if secret == nil {
		return nil, errors.New("Was not able to read list of certificates")
	}

	if secret.Data == nil {
		return res, errors.New("Got no data from backend")
	}

	for _, serial := range secret.Data["keys"].([]interface{}) {
		cert, revoked, err := fetchCertificateBySerial(serial.(string))
		if err != nil {
			return res, err
		}

		if revoked {
			continue
		}

		res = append(res, cert)
	}

	return res, nil
}

func revokeCertificateByFQDN(fqdn string) error {
	certs, err := fetchValidCertificatesFromVault()
	if err != nil {
		return err
	}

	for _, cert := range certs {
		if cert.Subject.CommonName == fqdn {
			if err := revokeCertificateBySerial(certutil.GetHexFormatted(cert.SerialNumber.Bytes(), ":")); err != nil {
				return err
			}
		}
	}

	return nil
}

func revokeCertificateBySerial(serial string) error {
	cert, revoked, err := fetchCertificateBySerial(serial)
	if err != nil {
		return err
	}
	if revoked {
		return nil
	}

	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "revoke"}, "/")
	if _, err := client.Logical().Write(path, map[string]interface{}{
		"serial_number": serial,
	}); err != nil {
		return fmt.Errorf("Revoke of serial %q failed: %s", serial, err.Error())
	}
	log.WithFields(log.Fields{
		"cn":     cert.Subject.CommonName,
		"serial": serial,
	}).Info("Revoked certificate")

	return nil
}

func getCAChain() (string, error) {
	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "cert", "ca_chain"}, "/")
	cs, err := client.Logical().Read(path)
	if err != nil {
		return "", errors.New("Unable to read ca_chain: " + err.Error())
	}

	if cs.Data == nil {
		return "", errors.New("Unable to read ca_chain: Empty")
	}

	cert, ok := cs.Data["certificate"]
	if !ok || len(cert.(string)) == 0 {
		return "", errors.New("Unable to read ca_chain: Empty")
	}

	return cert.(string), nil
}

func getCACert() (string, error) {
	path := strings.Join([]string{strings.Trim(cfg.PKIMountPoint, "/"), "cert", "ca"}, "/")
	cs, err := client.Logical().Read(path)
	if err != nil {
		return "", errors.New("Unable to read certificate: " + err.Error())
	}

	return cs.Data["certificate"].(string), nil
}

func fetchOvpnKey(fqdn string) (string, error) {
	path := strings.Join([]string{"secret", "data", strings.Trim(cfg.OvpnKey, "/")}, "/")
	secret, err := client.Logical().Read(path)

	if err != nil {
		return "", err
	}

	if secret == nil {
		return "", errors.New("Got no data from backend")
	}
	return secret.Data["data"].(map[string]interface {})["key"].(string), nil
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
	}).Debug("Generated new certificate")

	return &templateVars{
		Certificate: secret.Data["certificate"].(string),
		PrivateKey:  secret.Data["private_key"].(string),
	}, nil
}
