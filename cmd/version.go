package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Displays the version of the utility",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("vault-openvpn %s\n", version)
	},
}

func init() {
	RootCmd.AddCommand(versionCmd)
}
