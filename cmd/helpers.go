package cmd

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"strings"
	"text/template"
	"time"

	"github.com/hashicorp/vault/api"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

func fetchCertificateBySerial(serial string) (*x509.Certificate, bool, error) {
	path := strings.Join([]string{strings.Trim(viper.GetString("pki-mountpoint"), "/"), "cert", serial}, "/")
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

	if cert.NotAfter.Before(time.Now()) {
		// Hide expired certs (they will not get the revoke-timestamp set on revoke)
		revoked = true
	}

	return cert, revoked, err
}

func fetchOVPNKey() (string, error) {
	path := strings.Trim(viper.GetString("ovpn-key"), "/")
	secret, err := client.Logical().Read(path)

	if err != nil {
		return "", err
	}

	if secret == nil || secret.Data == nil {
		return "", errors.New("Got no data from backend")
	}

	key, ok := secret.Data["key"]
	if !ok {
		return "", errors.New("Within specified secret no entry named 'key' was found")
	}

	return key.(string), nil
}

func fetchValidCertificatesFromVault() ([]*x509.Certificate, error) {
	res := []*x509.Certificate{}

	path := strings.Join([]string{strings.Trim(viper.GetString("pki-mountpoint"), "/"), "certs"}, "/")
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

func generateCertificate(fqdn string) (*templateVars, error) {
	path := strings.Join([]string{strings.Trim(viper.GetString("pki-mountpoint"), "/"), "issue", viper.GetString("pki-role")}, "/")
	secret, err := client.Logical().Write(path, map[string]interface{}{
		"common_name": fqdn,
		"ttl":         viper.GetDuration("ttl").String(),
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

func generateCertificateConfig(tplName, fqdn string) error {
	if viper.GetBool("auto-revoke") {
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

	if viper.GetString("ovpn-key") != "" {
		tplv.TLSAuth, err = fetchOVPNKey()
		if err != nil {
			return fmt.Errorf("Could not fetch TLSAuth key: %s", err)
		}
	}

	if err := renderTemplate(tplName, tplv); err != nil {
		return fmt.Errorf("Could not render configuration: %s", err)
	}

	return nil
}

func getCACert() (string, error) {
	path := strings.Join([]string{strings.Trim(viper.GetString("pki-mountpoint"), "/"), "cert", "ca"}, "/")
	cs, err := client.Logical().Read(path)
	if err != nil {
		return "", errors.New("Unable to read certificate: " + err.Error())
	}

	return cs.Data["certificate"].(string), nil
}

func getCAChain() (string, error) {
	path := strings.Join([]string{strings.Trim(viper.GetString("pki-mountpoint"), "/"), "cert", "ca_chain"}, "/")
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

func initVaultClient() error {
	// Ensure token is present
	if viper.GetString("vault-token") == "" {
		return fmt.Errorf("You need to set vault-token")
	}

	clientConfig := api.DefaultConfig()
	clientConfig.ReadEnvironment()
	clientConfig.Address = viper.GetString("vault-addr")

	var err error
	client, err = api.NewClient(clientConfig)
	if err != nil {
		return fmt.Errorf("Could not create Vault client: %s", err)
	}

	client.SetToken(viper.GetString("vault-token"))

	return nil
}

func renderTemplate(tplName string, tplv *templateVars) error {
	raw, err := ioutil.ReadFile(path.Join(viper.GetString("template-path"), tplName))
	if err != nil {
		return err
	}

	tpl, err := template.New("tpl").Parse(string(raw))
	if err != nil {
		return err
	}

	return tpl.Execute(os.Stdout, tplv)
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
