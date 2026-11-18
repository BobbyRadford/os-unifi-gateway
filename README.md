# UniFi Gateway for OPNsense

This project makes an OPNsense router appear in a UniFi Network controller as a UniFi gateway. The controller then shows the router's WAN and LAN status, traffic, clients, apps and traffic flows alongside your UniFi access points and switches, as it would for a Ubiquiti gateway. It can also work in the other direction: networks, DHCP, port forwards, DNS records, routes and blocking that you set up in UniFi are applied to OPNsense.

The router appears as a **UniFi Gateway Pro (UXG-Pro)** running Ubiquiti's latest firmware, so the controller never offers an upgrade. The WAN is reported on the Pro's first port and the LAN on its second.

This repository is a fork of [rtm516/os-unifi-gateway](https://github.com/rtm516/os-unifi-gateway). It adds per-client traffic from the firewall states, apps and countries, Traffic Flows, and applying UniFi settings to OPNsense.

## Contents

- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Setting up OPNsense](#setting-up-opnsense)
- [Installing](#installing)
- [Adopting the gateway](#adopting-the-gateway)
- [What UniFi shows](#what-unifi-shows)
- [Managing OPNsense from UniFi](#managing-opnsense-from-unifi)
- [Configuration reference](#configuration-reference)
- [Development](#development)

## How it works

A daemon talks to the controller the way a UniFi gateway does. It sends the controller the router's state every few seconds (the "inform"), and the controller sends back its settings for the gateway. The daemon reads the router's state, and with apply mode on it also changes the router's settings.

```
┌──────────────────────┐   REST API    ┌──────────────────┐   inform (HTTP, AES)   ┌──────────────────┐
│ OPNsense             │ ◄───────────► │ the daemon       │ ─────────────────────► │ UniFi Network    │
│  interfaces, states, │               │  (a container or │ ◄───────────────────── │ controller       │
│  DHCP, DNS, ntopng   │               │  any Linux host) │   settings, adoption   │                  │
└──────────────────────┘               └──────────────────┘                        └──────────────────┘
```

The daemon can run in two places:

| | On another machine (recommended) | On the router, as an OPNsense plugin |
|---|---|---|
| Reads the router through | the OPNsense REST API, with an API key | OPNsense's own services, no key needed |
| Reports everything in [What UniFi shows](#what-unifi-shows) | yes | yes |
| Applies UniFi settings to OPNsense | yes | no |
| The UniFi speed test measures | that machine's internet connection | the router's WAN |
| Install | a Proxmox container, systemd, Docker or from source | a package you build from this repository |

Running it on another machine is what this fork is built and tested with. The published plugin package (from upstream's package repository) doesn't include this fork's changes.

## Requirements

- An OPNsense router. This fork is tested on OPNsense 26.7 with Kea DHCP and Unbound DNS. Dnsmasq DHCP works for reporting.
- A UniFi Network controller. This fork is tested on UniFi Network 10.6 running on UniFi OS Server.
- For running off the router, Python 3 with `requests`, `cryptography` and `dnspython` (or Docker, which installs them).

Some features need more on the OPNsense side. Everything not listed here works with the basics above.

| Feature | Needs |
|---|---|
| WAN latency, uptime and downtime | monitoring on the WAN gateway |
| Apps per client, destination names in Traffic Flows | the os-ntopng plugin |
| Region blocking | a GeoIP source (a free MaxMind account) |
| Multicast DNS between networks | the os-mdns-repeater plugin |
| Dynamic DNS | the os-ddclient plugin |
| Anything under [Managing OPNsense from UniFi](#managing-opnsense-from-unifi) | the daemon running off the router |

## Setting up OPNsense

### API user

Skip this when running the daemon on the router.

Create a user under **System > Access > Users**, give it the privileges below, and generate an API key for it. OPNsense downloads the key as `apikey.txt`. Only **Status: Interfaces** is required. Without one of the others, the daemon logs which privilege is missing and leaves that part out.

These privileges are for reporting:

| Privilege | Used for |
|---|---|
| Status: Interfaces | **required**: interfaces, addresses, counters |
| Lobby: Dashboard | hostname, version, uptime, CPU, memory, load average |
| Diagnostics: ARP Table | the client list |
| Diagnostics: Show States | per-client traffic, countries and allowed Traffic Flows |
| Diagnostics: Logs: Firewall: Live View | blocked Traffic Flows |
| Diagnostics: Network Insight | client names from reverse DNS |
| Services: DHCP: Kea(v4) *or* Services: Dnsmasq DNS/DHCP: Settings | client names and the LAN's DHCP range from DHCP |
| Services: Unbound | the WAN DNS servers |
| System: Gateways | WAN latency, uptime and downtime |
| Diagnostics: Ping | a client's **Ping Test** |

Apply mode also needs these. Each one also lets the key change that part of OPNsense.

| Privilege | Used for |
|---|---|
| Interfaces: VLAN | VLANs for UniFi networks |
| Interfaces: Assign network ports | interfaces for those VLANs |
| Firewall: Rules [new] | rules for networks, isolation and region blocking |
| Firewall: NAT: Destination NAT | port forwards |
| Firewall: Alias: Edit | region blocking |
| Services: DHCP: Kea(v4) | DHCP ranges, options and reservations |
| Services: Unbound | DNS records, ad blocking and app blocking |
| System: Static Routes | static routes |
| System: Gateways | gateways for static routes |
| Services: mDNS Repeater | multicast DNS between networks |
| Services: Dynamic DNS | Dynamic DNS |

### WAN gateway monitoring

UniFi's WAN latency, uptime and downtime come from OPNsense's gateway monitoring (dpinger). Under **System > Gateways > Configuration**, edit the WAN gateway, make sure **Disable Gateway Monitoring** is unticked, and save.

### ntopng

A UniFi gateway knows which app each connection belongs to (YouTube, Netflix and so on) from deep packet inspection. Here ntopng does that job. It fills a client's Traffic Activity and the apps in **Insights > Activity**, and it names the destinations in Traffic Flows.

1. Install **os-ntopng** under **System > Firmware > Plugins**. It brings Redis with it.
2. Under **Services > ntopng**, enable it and select the LAN and each VLAN interface.
3. Open ntopng (port 3000 on the router) and set the admin password at the first login.
4. Put the password in a file next to the daemon's config and point the daemon at ntopng:

   ```ini
   [ntopng]
   url = http://192.168.1.1:3000
   password_file = /var/lib/opnsense-unifi/ntopng-password.txt
   ```

### GeoIP source for region blocking

OPNsense needs a country database to block countries. MaxMind's GeoLite2 database is free with an account.

1. Sign up for GeoLite at [maxmind.com](https://www.maxmind.com/en/geolite2/signup).
2. Note your account ID, and create a license key under **Manage License Keys**.
3. In OPNsense, open **Firewall > Aliases > GeoIP settings** and set the URL to:

   ```
   https://ACCOUNT_ID:LICENSE_KEY@download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip
   ```

Use this URL form, with the account ID. The older `geoip_download?license_key=...` URL can reject a newer license key as invalid.

### Plugins for mDNS and Dynamic DNS

Install **os-mdns-repeater** for UniFi's Multicast DNS setting and **os-ddclient** for its Dynamic DNS. The daemon skips each feature, and logs a warning, while its plugin is missing.

## Installing

### In a Proxmox container

`contrib/proxmox/create-lxc.sh` creates a small Debian container that runs the daemon as a systemd service. Copy it to the Proxmox host and run it as root:

```sh
CONTROLLER=10.0.0.5 OPNSENSE_HOST=10.0.0.1 \
OPNSENSE_API_KEY_FILE=/root/apikey.txt BRIDGE=vmbr1 ./create-lxc.sh
```

The container starts on boot and is tagged `unifi` and `opnsense`. Its notes in the Proxmox UI say where the logs, code and state live and how to update it. A new install starts in plan mode, so it only logs what it would change in OPNsense. To move a daemon that is already adopted without adopting it again, set `STATE_DIR` to a copy of its `/var/lib/opnsense-unifi`. The header of the script lists every setting.

### As a systemd service

`contrib/opnsense-unifi.service` runs the daemon on any Debian-like host with systemd. Its header lists the install steps.

### In Docker

Put `apikey.txt` in `conf/`, set the router address and the controller's inform URL in `docker-compose.yml`, and start it:

```sh
docker compose up -d --build
docker compose logs -f
```

`conf/unifi-gateway.conf` is created on the first start. To see what the daemon would send without talking to a controller, run `docker compose run --rm unifi-gateway dump`.

### From source

```sh
pip install -r requirements.txt
OPNSENSE_HOST=192.168.1.1 OPNSENSE_API_KEY_FILE=apikey.txt \
UNIFI_ADOPT_URL=http://controller:8080/inform python unifi_gateway.py run
```

The commands are `run` (in the foreground), `set-adopt -s <url>`, `dump` and `status`.

### As an OPNsense plugin

Build the package as described under [Building the plugin](#building-the-plugin), copy it to the router, and install it from the OPNsense shell (**System > Console** or SSH):

```sh
pkg add os-unifi-gateway-<version>.pkg
```

Then open **Services > UniFi Gateway**, tick **Enable**, enter the controller's inform URL, pick the WAN and LAN interfaces, and click **Apply**. **Services > UniFi Gateway > Log File** shows what the daemon is doing. The plugin keeps its config in `/var/db/unifi-gateway/unifi-gateway.conf`, which is where `[ntopng]` goes. To remove it, run `pkg delete os-unifi-gateway`.

## Adopting the gateway

1. Start the daemon with the controller's inform URL, usually `http://<controller>:8080/inform`. Set it with `UNIFI_ADOPT_URL`, `[gateway] url` or the plugin's settings page.
2. In the controller, the gateway shows up under UniFi Devices as a pending **UniFi Gateway Pro**. Click **Adopt**.

The daemon keeps its adoption in its config file. If the controller forgets the gateway, the daemon announces itself again and waits to be adopted.

A gateway adopted with an older version that emulated a UniFi Gateway Lite stays a Gateway Lite in the controller, with its WAN and LAN ports swapped, and the log says so at every start. Forget it in the controller and adopt it again to make it a Gateway Pro.

## What UniFi shows

| Controller shows | Comes from |
|---|---|
| WAN and LAN addresses, MACs, link state, MTU, speed | interface status |
| Traffic counters and rates | interface statistics |
| WAN gateway, latency, uptime and downtime | the routing table and gateway monitoring |
| ISP name and logo | the WAN address's provider, from [Team Cymru](https://www.team-cymru.com/ip-asn-mapping)'s IP-to-ASN DNS service |
| WAN DNS servers | Unbound's upstream servers, otherwise the WAN link's DNS servers |
| Clients and their traffic | the ARP table, DHCP leases and the firewall states |
| Client names | the client's Kea reservation, else its DHCP lease name, else DNS or ARP |
| A client's Traffic Activity, the apps in Insights > Activity | ntopng |
| Traffic Flows, the clients in Insights > Activity | the firewall states (allowed) and the firewall log (blocked) |
| Destination names in Traffic Flows | ntopng |
| Traffic per country | the firewall states, with [DB-IP](https://db-ip.com)'s free country database |
| Hostname, uptime, CPU, memory, load average | system information |
| WAN speed test | measured by the daemon against the nearest [speedtest.net](https://www.speedtest.net) server |
| A client's Ping Test | the firewall pings the client |

**Client traffic.** The firewall's state table holds the bytes each connection has carried. The daemon reads it every 10 seconds, on the LAN and every VLAN alike. pf keeps a connection's state for at least 30 seconds after its last packet, so short connections count too. Counting starts when the daemon starts, so connections already open then count from that moment. IPv6 traffic isn't counted, because the client list goes by IPv4 address.

**Traffic Flows.** The same reads send each new or active connection to the controller, which keeps them as Traffic Flows. The Flows tab lists them, and Insights > Activity ranks clients by how many flows they made. Every 10 seconds the daemon also sends what the firewall log recorded as blocked since its last read, which shows as blocked flows. Their policy is the OPNsense rule's, which UniFi doesn't know by name. With ntopng set up, a flow's destination shows the name ntopng learned for that server from the DNS answers it saw.

**Apps.** The daemon reads each client's apps from ntopng once a minute and reports them under UniFi's own app IDs. 152 of nDPI's apps have a UniFi counterpart (`collectors/ndpi_apps.json`, made by `dev/make_ndpi_apps.py`), and the rest show as Unknown. ntopng's numbers only split each client's traffic between apps, so they can differ a little from the firewall's totals.

**Countries.** The daemon downloads DB-IP's free IP to Country Lite database each month into `dbip-country-lite.mmdb` next to its config file. Set `file` under `[geoip]` to move it, or leave it empty to turn this off. IP Geolocation by [DB-IP](https://db-ip.com).

**Speed test.** **ISP Speed Test** on the dashboard, or the controller's schedule, runs a test with live progress. It picks the lowest-latency of the nearest speedtest.net servers, then measures each direction for at least 10 seconds over 8 connections, so results should match speedtest.net. It runs where the daemon runs, so off the router it measures that machine's connection. The last result is kept in `speedtest.json` next to the config file.

## Managing OPNsense from UniFi

With apply mode on, the daemon makes OPNsense match what you set in UniFi. The controller sends a gateway its whole configuration whenever something changes, and the daemon applies it through the REST API. This only works with the daemon running off the router.

### What gets applied

| Set in UniFi | Changes in OPNsense |
|---|---|
| A network with a VLAN ID and a gateway IP | a VLAN on the LAN NIC, an interface with the gateway address, a Kea subnet or Dnsmasq range, and a rule passing its traffic |
| Isolate network | rules ahead of it blocking each of the other local networks |
| A network's DHCP range and lease time | the Kea subnet's pool, or the Dnsmasq range, and its lease time |
| A network's DHCP gateway, DNS servers, NTP servers and domain name | the Kea subnet's options, or Dnsmasq options and the range's domain |
| Fixed IP on a client | a Kea reservation, or a Dnsmasq host, for its MAC |
| Port forwarding rules | Destination NAT rules, each passing its own traffic |
| DNS records (A and AAAA) | Unbound host overrides |
| Static routes (next hop or blackhole) | static routes, through a gateway with the next hop's address (added if missing) or Null4/Null6 |
| Ad Blocking (CyberSecure) | an Unbound blocklist (AdGuard) for those networks |
| Traffic rules that block an app or a category | an Unbound blocklist of the apps' domains for the rule's source networks |
| Region Blocking, in block mode (CyberSecure) | a GeoIP alias of the countries, floating block rules that log what they block, and a "no RDR" rule so port forwards are covered |
| Multicast DNS between networks | os-mdns-repeater's interfaces |
| Dynamic DNS | os-ddclient accounts |

### Turning it on

1. Make the network in UniFi match OPNsense (subnet, DHCP range, lease time). Otherwise the first push changes OPNsense to UniFi's values. Adoption already copies the subnet and range.
2. Set `[apply] mode = plan`. The daemon then logs what it would change ("Would apply: ...") without changing anything.
3. When the log shows only changes you want, set `mode = apply`.

The daemon applies the configuration once at start and again each time the controller sends a new one. It keeps each configuration it receives in `system_cfg.json`, with every version in `system_cfg-history/`. Both are readable only by the daemon's user, because they include the site's secrets.

### What the daemon changes and leaves alone

The daemon only deletes what it created. Its objects have descriptions starting with `[unifi]`. Anything made by hand stays, though a hand-made reservation or host override is updated if UniFi asks for a different address for the same MAC or name.

DHCP goes to the server `[opnsense] dhcp` names. `auto` picks Kea when it is enabled, else Dnsmasq when it is, else Kea; `isc` and `none` leave DHCP alone. The daemon creates a Kea subnet or Dnsmasq range only for a VLAN network it built, so the LAN's own one has to exist in OPNsense already.

- **Kea.** On a hand-made Kea subnet such as the LAN, the daemon sets only the options UniFi sets, which turns Kea's option autocollect off for that subnet.
- **Dnsmasq.** A network's scope is the IPv4 range that starts inside it. Dnsmasq already gives clients the interface address as router and DNS server, so an option is only added where UniFi sets something else, and a hand-made option for the same interface and number is updated instead. Fixed IPs are matched against every Dnsmasq host by MAC (a host with more than one MAC isn't moved). When Dnsmasq has no interfaces selected it answers on all of them, and the daemon leaves that alone.

### Limits

- **Networks.** VLAN-only networks are left alone, because the gateway doesn't route them. As in UniFi, an isolated network can't start connections to the other local networks, but they can still reach it. Switch ports and Wi-Fi networks carry the VLAN as UniFi configures them, and a Proxmox bridge between the router and the switch has to pass tagged frames (a bridge without VLAN awareness does). Clients that no UniFi switch or access point reports show under the default network, whatever their VLAN.
- **App blocking.** OPNsense can't match traffic by app, so app blocking blocks the DNS lookups of the domains nDPI knows for each app (`app_domains.json`, made by `dev/make_app_domains.py`). Devices that use their own DNS (DNS over HTTPS, a VPN) get past it, and apps without known domains aren't blocked. A rule's schedule, and sources other than networks, aren't applied. A new block takes effect once clients' cached DNS answers expire, usually within minutes.
- **Region blocking.** It needs the [GeoIP source](#geoip-source-for-region-blocking). UniFi's "allow" mode isn't applied, because it would block local traffic too.
- **mDNS and Dynamic DNS.** They need their plugins. UniFi's mDNS service filter isn't applied, so every service is repeated. Custom Dynamic DNS services other than Namecheap are skipped.
- **Not applied at all.** UPnP (the OPNsense UPnP plugin has no API), interface routes, firewall rules other than app blocking, and IPS. UniFi's IPS alerts come from Ubiquiti's cloud, so they can't be fed from OPNsense.

## Configuration reference

The daemon reads `conf/unifi-gateway.conf`, or the file named by `UNIFI_GW_CONFIG`. It creates the file on its first start and stores its adoption state there. Don't edit the adoption settings by hand.

### Config file

```ini
[opnsense]
# api (default, off the router) or local (on the router)
# source = api
host = 192.168.1.1
api_key =
api_secret =
# api_key_file = /path/to/apikey.txt
verify_ssl = False
# timeout = 15
# Interfaces are matched by description, then identifier (wan, lan, opt1), then device
# wan_interface = WAN
# lan_interface = LAN
# DHCP server for leases and for [apply]: auto, dnsmasq, kea, isc or none
# (isc and none leave DHCP alone when applying)
# dhcp = auto

[gateway]
# firmware = latest
# hostname = my-gateway
# speedtest_file = /path/to/speedtest.json

[apply]
# off, plan or apply (needs source = api)
# mode = off

[ntopng]
# url = http://192.168.1.1:3000
# user = admin
# password_file = /path/to/ntopng-password.txt

[geoip]
# The country database for traffic per country, by default next to this file;
# empty turns it off
# file = /var/lib/opnsense-unifi/dbip-country-lite.mmdb
```

### Environment variables

Environment variables override the config file for that run and are never written back to it.

| Variable | Setting |
|---|---|
| `OPNSENSE_HOST` | Router address (IP or hostname, optionally with scheme and port) |
| `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET` | API credentials |
| `OPNSENSE_API_KEY_FILE` | Path to the `apikey.txt` OPNsense downloads |
| `OPNSENSE_VERIFY_SSL` | `true` to verify the router's certificate against [certifi](https://pypi.org/project/certifi/)'s CAs. For a router with a private CA, also set `REQUESTS_CA_BUNDLE` to the CA file. |
| `OPNSENSE_WAN_INTERFACE`, `OPNSENSE_LAN_INTERFACE` | Interfaces to report (default `WAN` and `LAN`) |
| `UNIFI_ADOPT_URL` | Controller inform URL |
| `UNIFI_GW_FIRMWARE` | Pin the reported firmware instead of tracking the latest |
| `UNIFI_GW_HOSTNAME` | Hostname reported to the controller (default: the router's hostname) |
| `UNIFI_GW_SOURCE` | `api` (default) or `local` (on the router) |
| `UNIFI_GW_APPLY` | `off` (default), `plan` or `apply` |
| `UNIFI_GW_CONFIG` | Config file path (default `conf/unifi-gateway.conf`) |
| `UNIFI_GW_LOG_LEVEL` | `DEBUG`, `INFO`, `WARNING` or `ERROR` |
| `UNIFI_GW_LOG_FILE` | Log to a file instead of stderr |

## Development

```sh
pip install -r requirements.txt pytest jinja2
python -m pytest
```

| Path | Purpose |
|---|---|
| `unifi_gateway.py` | Entry point: adoption, the inform loop, controller responses, config handling |
| `unifi_protocol.py` | Inform packets (TNBU header, AES-CBC/GCM, zlib/snappy) and payloads |
| `provision.py` | Keeps each configuration the controller sends |
| `reconcile.py` | Applies the controller's configuration to OPNsense |
| `devices.py` | The emulated model and the latest-firmware lookup |
| `speedtest.py` | The controller's WAN speed test, against speedtest.net servers |
| `pingtest.py` | The controller's client Ping Test |
| `isp.py` | Looks up the WAN's ISP |
| `aes.py` | AES-CBC/GCM for inform packets |
| `collectors/opnsense.py` | Turns router state into what the inform needs |
| `collectors/traffic.py` | Per-client traffic and Traffic Flows from the firewall states and log |
| `collectors/ntopng.py` | Apps and destination names from ntopng |
| `collectors/geoip.py` | The country database |
| `collectors/source.py` | The interface between the collector and the router |
| `collectors/local_source.py` | On the router: configd and `config.xml` (used by the plugin) |
| `collectors/api_source.py` | Off the router: the REST API |
| `dev/` | Scripts that regenerate `collectors/ndpi_apps.json` and `app_domains.json` |
| `contrib/` | The Proxmox container script and the systemd unit |
| `plugin/` | The OPNsense plugin, laid out like [opnsense/plugins](https://github.com/opnsense/plugins) |

### Building the plugin

`plugin/build-pkg.sh` builds the package and `plugin/build-repo.sh` the package repository. Both need FreeBSD's `pkg`. `plugin/Dockerfile.pkg` builds it for Linux, so packages can be made on any machine with Docker:

```sh
docker build -t unifi-gateway-pkg -f plugin/Dockerfile.pkg plugin
docker run --rm -v "$PWD:/src" -w /src unifi-gateway-pkg sh plugin/build-pkg.sh 0.1.0 dist
```

Pushing a `v*` tag builds the plugin package, attaches it to a GitHub release, publishes it to the `pkg-repo` branch (served by GitHub Pages) and pushes the Docker image to GHCR.

## License

MIT. See [LICENSE](LICENSE).

## Acknowledgments

- [rtm516/os-unifi-gateway](https://github.com/rtm516/os-unifi-gateway): the OPNsense plugin this fork is based on
- [amd989/unifi-gateway](https://github.com/amd989/unifi-gateway): the inform protocol, adoption flow and payloads the plugin builds on
- [stephanlascar/unifi-gateway](https://github.com/stephanlascar/unifi-gateway): the original UniFi gateway emulator
- [qvr/unifi-gateway](https://github.com/qvr/unifi-gateway): the Python 3 port, FreeBSD support and AES-GCM

Protocol documentation:

- [jk-5/unifi-inform-protocol](https://github.com/jk-5/unifi-inform-protocol)
- [fxkr/unifi-protocol-reverse-engineering](https://github.com/fxkr/unifi-protocol-reverse-engineering)
