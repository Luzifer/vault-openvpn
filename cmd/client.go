package cmd

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// clientCmd represents the client command
var clientCmd = &cobra.Command{
	Use:     "client <fqdn>",
	Short:   "Generate certificate and output client config",
	PreRunE: func(cmd *cobra.Command, args []string) error { return initVaultClient() },
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 || !validateFQDN(args[0]) {
			return errors.New("You need to provide a valid FQDN")
		}

		return generateCertificateConfig("client.conf", args[0])
	},
}

func init() {
	RootCmd.AddCommand(clientCmd)

	clientCmd.Flags().BoolVar(&cfg.AutoRevoke, "auto-revoke", true, "Automatically revoke older certificates for this FQDN")
	clientCmd.Flags().DurationVar(&cfg.CertTTL, "ttl", 8760*time.Hour, "Set the TTL for this certificate")
	clientCmd.Flags().StringVar(&cfg.OVPNKey, "ovpn-key", "", "Specify a secret name that holds an OpenVPN shared key")

	clientCmd.Flags().StringVar(&cfg.TemplatePath, "template-path", ".", "Path to read the client.conf / server.conf template from")
	viper.BindPFlags(clientCmd.Flags())
}
