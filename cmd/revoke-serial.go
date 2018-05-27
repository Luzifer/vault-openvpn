package cmd

import (
	"errors"
	"fmt"
	"strings"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// revokeSerialCmd represents the revoke-serial command
var revokeSerialCmd = &cobra.Command{
	Use:   "revoke-serial <serial>",
	Short: "Revoke certificate by serial number",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 || !validateSerial(args[0]) {
			return errors.New("You need to provide a valid serial")
		}

		return revokeCertificateBySerial(args[0])
	},
}

func init() {
	RootCmd.AddCommand(revokeSerialCmd)
}

func revokeCertificateBySerial(serial string) error {
	cert, revoked, err := fetchCertificateBySerial(serial)
	if err != nil {
		return err
	}
	if revoked {
		return nil
	}

	path := strings.Join([]string{strings.Trim(viper.GetString("pki-mountpoint"), "/"), "revoke"}, "/")
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
