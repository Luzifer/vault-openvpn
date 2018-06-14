package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	homedir "github.com/mitchellh/go-homedir"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

const dateFormat = "2006-01-02 15:04:05"

var (
	cfg = struct {
		ConfigFile string

		VaultAddress string
		VaultToken   string

		PKIMountPoint string
		PKIRole       string

		AutoRevoke bool
		CertTTL    time.Duration
		OVPNKey    string

		LogLevel     string
		Sort         string
		TemplatePath string
	}{}

	version string

	client *api.Client
)

// RootCmd represents the base command when called without any subcommands
var RootCmd = &cobra.Command{
	Use:   "vault-openvpn",
	Short: "Manage OpenVPN configuration combined with a Vault PKI",

	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Configure log level
		if logLevel, err := log.ParseLevel(viper.GetString("log-level")); err == nil {
			log.SetLevel(logLevel)
		} else {
			return fmt.Errorf("Unable to interprete log level: %s", err)
		}

		return nil
	},
}

// Execute adds all child commands to the root command sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(ver string) {
	version = ver
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	RootCmd.PersistentFlags().StringVar(&cfg.ConfigFile, "config", "", "config file (default is $HOME/.config/vault-openvpn.yaml)")

	RootCmd.PersistentFlags().StringVar(&cfg.VaultAddress, "vault-addr", "https://127.0.0.1:8200", "Vault API address")
	RootCmd.PersistentFlags().StringVar(&cfg.VaultToken, "vault-token", "", "Specify a token to use (~/.vault-token file is taken into account)")

	RootCmd.PersistentFlags().StringVar(&cfg.PKIMountPoint, "pki-mountpoint", "/pki", "Path the PKI provider is mounted to")
	RootCmd.PersistentFlags().StringVar(&cfg.PKIRole, "pki-role", "openvpn", "Role defined in the PKI usable by the token and able to write the specified FQDN")

	RootCmd.PersistentFlags().StringVar(&cfg.LogLevel, "log-level", "info", "Log level to use (debug, info, warning, error)")

	viper.BindPFlags(RootCmd.PersistentFlags())
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_"))

	if tok := vaultTokenFromDisk(); tok != "" {
		viper.SetDefault("vault-token", tok)
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig() {
	if cfg.ConfigFile != "" { // enable ability to specify config file via flag
		viper.SetConfigFile(cfg.ConfigFile)
	}

	viper.SetConfigName("vault-openvpn") // name of config file (without extension)
	viper.AddConfigPath("$HOME")         // adding home directory as first search path
	viper.AddConfigPath("$HOME/.config") // adding config directory as second search path
	viper.AutomaticEnv()                 // read in environment variables that match

	// If a config file is found, read it in.
	if err := viper.ReadInConfig(); err == nil {
		log.Debugf("Using config file: %s", viper.ConfigFileUsed())
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
