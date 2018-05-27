package cmd

import "time"

type templateVars struct {
	CertAuthority string
	Certificate   string
	PrivateKey    string
	TLSAuth       string
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
