# Config Domain / Origin Workflow

A tunnel can bind a client configuration to an Iranian/Cloudflare hostname while
keeping the actual public transport endpoint outside the Iran server.

- `config_domain`: hostname shown inside VLESS/Trojan/SS/MTProto configs.
- `origin_host`: external origin/host information for the outside server.
- `published_host`: Railway public proxy hostname created by the tunnel.
- `dns_target`: the published endpoint to which the Config Domain should point.
- `link_id`: the existing panel config tied to the tunnel.

The generated share link uses `config_domain` for the client-visible address when
a tunnel is bound to that config. The actual Rathole transport remains the
published Railway endpoint. The panel exposes the CNAME target explicitly.

Important: this does not magically create Cloudflare DNS records. The DNS record
must point the Config Domain to the published endpoint unless the project is
extended with a configured Cloudflare API token/zone.
