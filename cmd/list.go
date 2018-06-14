package cmd

import (
	"encoding/json"
	"os"
	"sort"

	"github.com/hashicorp/vault/helper/certutil"
	"github.com/olekukonko/tablewriter"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

// listCmd represents the list command
var listCmd = &cobra.Command{
	Use:     "list",
	Short:   "List all valid (not expired, not revoked) certificates",
	PreRunE: func(cmd *cobra.Command, args []string) error { return initVaultClient() },
	RunE: func(cmd *cobra.Command, args []string) error {
		return listCertificates()
	},
}

func init() {
	RootCmd.AddCommand(listCmd)

	listCmd.Flags().StringVar(&cfg.Sort, "sort", "fqdn", "How to sort list output (fqdn, issuedate, expiredate)")
	listCmd.Flags().Bool("list-expired", false, "Also list expired certificates")
	listCmd.Flags().String("format", "table", "Format to display the certificates in (table, json)")
	viper.BindPFlags(listCmd.Flags())
}

func listCertificates() error {
	lines := []listCertificatesTableRow{}

	certs, err := fetchCertificatesFromVault(viper.GetBool("list-expired"))
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
		switch viper.GetString("sort") {
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

	switch viper.GetString("format") {
	case "json":
		return json.NewEncoder(os.Stdout).Encode(lines)

	default:
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{"FQDN", "Not Before", "Not After", "Serial"})
		table.SetBorder(false)

		for _, line := range lines {
			table.Append(line.ToLine())
		}

		table.Render()
		return nil
	}
}
