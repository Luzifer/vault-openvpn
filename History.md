# 1.4.0 / 2018-05-27

- Add support for imported root certificates by reading `ca_chain`  
  Thanks @wimfabri for the addition
- Add support for directly writing `tls-auth` to harden OpenVPN connection  
  Thanks @callidus for the addition

# 1.3.0 / 2018-01-30

  * revoke all existing certificates for FQDN instead of only first one (Thanks @wimfabri)

# 1.2.0 / 2018-01-13

  * Allow sorting by date instead of FQDN

# 1.1.2 / 2017-11-10

  * Add dockerized version

# 1.1.1 / 2017-10-10

  * Fix: Don't panic on non existent PKI path
  * Update dependencies
  * Update README.md

# 1.1.0 / 2017-05-04

  * Allow path to templates to be configured

# 1.0.0 / 2017-05-04

This is a major release as it modified the default behaviour:
- Certificates are not longer listed when creating a new config but instead there is a `list` command for this
- Revoked certificates are never listed
- Option to revoke older certificates with the same FQDN is now enabled by default

Other changes:
  * Add Github releases building
  * Allow defining default config on disk  
    (Configuration is to be written to `~/.config/vault-openvpn.yaml`)
  * Add `list` and `revoke-serial` commands

# 0.3.0 / 2017-05-03

  * Improve logging output

# 0.2.0 / 2016-08-25

  * Add support for self-signed CAs that are in the OS trust store

# 0.1.2 / 2016-07-25

  * fix not enough arguments to return

# 0.1.1 / 2016-07-25

  * fix errors not being returned

# 0.1.0 / 2016-07-25

  * initial version
