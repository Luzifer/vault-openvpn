# Example: living-example

This example is the configuration I'm running for my personal VPN connection. Sure there are some modifications but that are customizations not relevant for this project.

## How to set up the server?

- Edit the `cloud-init.yml` file and set your own variables in `/etc/script_env`
- Create a DigitalOcean droplet using this config
- Replace the `myserver.com` part in the `client.conf` with your IP
- Generate a server configuration and put it into `/etc/openvpn/server.conf`  
```bash
# vault-openvpn --auto-revoke --pki-mountpoint luzifer_io server edda.openvpn.luzifer.io
server 10.231.0.0 255.255.255.0
route 10.231.0.0 255.255.255.0
[...]
```
- Ensure the server has finished generating `dh.pem` and reload the config: `systemctl restart openvpn`
- Generate a client configuration and put it into Tunnelblick or any other client software you like:  
```bash
# vault-openvpn --auto-revoke --pki-mountpoint luzifer_io client knut-ws02.openvpn.luzifer.io
remote myserver.com 1194 udp

client
nobind
dev tap

<ca>
[...]
```

