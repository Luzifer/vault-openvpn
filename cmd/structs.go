package cmd

import "time"

type templateVars struct {
	CertAuthority string
	Certificate   string
	PrivateKey    string
	TLSAuth       string
}

type listCertificatesTableRow struct {
	FQDN      string    `json:"fqdn"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	Serial    string    `json:"serial"`
}

func (l listCertificatesTableRow) ToLine() []string {
	return []string{
		l.FQDN,
		l.NotBefore.Format(dateFormat),
		l.NotAfter.Format(dateFormat),
		l.Serial,
	}
}
