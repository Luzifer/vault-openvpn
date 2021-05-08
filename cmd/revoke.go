package cmd

import (
	"errors"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"github.com/spf13/cobra"
)

// revokeCmd represents the revoke command
var revokeCmd = &cobra.Command{
	Use:     "revoke <fqdn>",
	Short:   "Revoke all certificates matching to FQDN",
	PreRunE: func(cmd *cobra.Command, args []string) error { return initVaultClient() },
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 || !validateFQDN(args[0]) {
			return errors.New("You need to provide a valid FQDN")
		}

		return revokeCertificateByFQDN(args[0])
	},
}

func init() {
	RootCmd.AddCommand(revokeCmd)
}

func revokeCertificateByFQDN(fqdn string) error {
	certs, err := fetchCertificatesFromVault(false)
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
