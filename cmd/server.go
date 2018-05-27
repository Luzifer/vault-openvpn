package cmd

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// serverCmd represents the server command
var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "Generate certificate and output server config",
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) != 1 || !validateFQDN(args[0]) {
			return errors.New("You need to provide a valid FQDN")
		}

		return generateCertificateConfig("server.conf", args[0])
	},
}

func init() {
	RootCmd.AddCommand(serverCmd)

	serverCmd.Flags().BoolVar(&cfg.AutoRevoke, "auto-revoke", true, "Automatically revoke older certificates for this FQDN")
	serverCmd.Flags().DurationVar(&cfg.CertTTL, "ttl", 8760*time.Hour, "Set the TTL for this certificate")
	serverCmd.Flags().StringVar(&cfg.OVPNKey, "ovpn-key", "", "Specify a secret name that holds an OpenVPN shared key")

	serverCmd.Flags().StringVar(&cfg.TemplatePath, "template-path", ".", "Path to read the client.conf / server.conf template from")
	viper.BindPFlags(serverCmd.Flags())
}
