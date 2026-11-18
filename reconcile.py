"""Make OPNsense match what the controller wants for this gateway.

The controller sends its whole configuration for the gateway as `system_cfg`
(see provision.py). `intent_from_system_cfg` reads the parts this project
supports out of it, and `Reconciler` changes OPNsense through its REST API
until it matches:

- Networks with a VLAN ID and a gateway address: a VLAN on the LAN port, an
  interface with the gateway address, a Kea subnet that Kea listens on, and
  a rule passing the network's traffic. An isolated network also gets a
  rule blocking the other local networks, as UniFi's isolation does: it
  can't start connections to them, but they can still reach it.
- DHCP (Kea): each subnet's address pool and lease time, its router, DNS
  servers, NTP servers and domain name, and its reservations ("Fixed IP" on
  a client in the UniFi UI), matched by MAC.
- Port forwards (Destination NAT), each with its own pass rule.
- DNS records from the UI's DNS page (A and AAAA), as Unbound host overrides.
- Ad blocking, as an Unbound blocklist for the networks that have it.
- App blocking (traffic rules that block an app or a category of apps), as
  an Unbound blocklist of the apps' domains for the rule's source networks.
  OPNsense can't match traffic by app, so this blocks the DNS lookups.
  app_domains.json lists the domains (see dev/make_app_domains.py).
- Firewall rules from the UI's LAN In and Internet In lists, as OPNsense
  rules ahead of the network rules, on every LAN interface or on the WAN.
  Addresses and ports that don't fit in one rule field become aliases.
- Static routes, through an existing gateway with the next hop's address or
  one the reconciler adds.
- Region blocking, as a GeoIP alias and floating block rules. OPNsense needs
  a GeoIP source (Firewall > Aliases > GeoIP settings) for this.
- mDNS between networks (os-mdns-repeater) and Dynamic DNS (os-ddclient),
  when those plugins are installed.

UniFi is the source of truth for everything listed above, but the reconciler
only ever deletes objects it created itself. It marks them by starting their
description with OWNER_TAG. Objects someone made by hand in OPNsense are
updated when UniFi asks for something different (a reservation for the same
MAC, say) but are never removed. A Kea subnet is only created for a network
the reconciler made, so the LAN's subnet has to exist already.

Set `[apply] mode` in the config file: `off` (default) does nothing, `plan`
only logs what it would change, and `apply` changes OPNsense.
"""
import hashlib
import ipaddress
import json
import logging
import os
import re
from dataclasses import dataclass, field

logger = logging.getLogger('unifi-gateway')

OWNER_TAG = '[unifi]'

# Where the network rules go in OPNsense's rule order (the default is 100)
RULE_SEQUENCE = 20000

# The UXG port the LAN runs on. Its VLANs become VLANs on OPNsense's LAN NIC.
LAN_PORT = 'eth1'
MODES = ('off', 'plan', 'apply')

# UniFi port forward protocols, as OPNsense names them
PROTOCOLS = {'tcp': 'tcp', 'udp': 'udp', 'tcp_udp': 'tcp/udp', 'tcp/udp': 'tcp/udp'}

# The Unbound blocklist used for UniFi's ad blocking (AdGuard's DNS filter)
AD_BLOCKLISTS = 'ag'

# Domains to block for each UniFi app ID ((category << 16) | app), from nDPI
with open(os.path.join(os.path.dirname(__file__), 'app_domains.json')) as _f:
    APP_DOMAINS = json.load(_f)

# Region blocking: the GeoIP alias and the descriptions of its rules
REGION_ALIAS = 'unifi_region_block'
REGION_DESCR = OWNER_TAG + ' Region blocking'

# Firewall rules: the UniFi chains that are applied, with the interfaces they
# go on ('lan' stands for every LAN interface), the actions and the protocols,
# as OPNsense names them
FIREWALL_CHAINS = {'LAN_IN': 'lan', 'WAN_IN': 'wan'}
FIREWALL_ACTIONS = {'RETURN': 'pass', 'ACCEPT': 'pass', 'DROP': 'block', 'REJECT': 'reject'}
FIREWALL_PROTOCOLS = {'all': 'any', 'tcp': 'TCP', 'udp': 'UDP', 'tcp_udp': 'TCP/UDP',
                      'icmp': 'ICMP', 'icmpv6': 'IPV6-ICMP'}
FIREWALL_DESCR = OWNER_TAG + ' Firewall'
FIREWALL_ALIAS = 'unifi_fw_'
# Where the firewall rules go in OPNsense's rule order, ahead of the network rules
FIREWALL_SEQUENCE = 10000

# UniFi Dynamic DNS services, as os-ddclient names them. UniFi sends Namecheap
# as a custom service (see _ddns_from). Services left out have no clear match.
DDNS_SERVICES = {
    'afraid': 'freedns', 'changeip': 'changeip', 'dnsomatic': 'dns-o-matic',
    'duckdns': 'duckdns', 'dyn': 'dyndns2', 'dyndns': 'dyndns2', 'easydns': 'easydns',
    'freemyip': 'freemyip', 'loopia': 'loopia', 'no-ip': 'noip', 'nsupdate': 'nsupdatev4',
    'ovh': 'ovh', 'sitelutions': 'sitelutions', 'spdyn': 'spdyn', 'strato': 'strato',
    'tunnelbroker': 'he-net-tunnel', 'zoneedit': 'zoneedit1',
}


# ── What the controller wants ────────────────────────────────────────────

@dataclass
class DhcpScope:
    subnet: str                         # "10.0.0.0/24"
    range_start: str
    range_stop: str
    lease_time: int
    reservations: dict = field(default_factory=dict)   # {mac: ip}
    dns_servers: list = field(default_factory=list)
    router: str = ''                    # the gateway clients get, UniFi's override if set
    domain: str = ''
    ntp_servers: list = field(default_factory=list)


@dataclass
class PortForward:
    name: str
    protocol: str                       # OPNsense name: tcp, udp, tcp/udp
    external_port: str
    internal_ip: str
    internal_port: str
    source: str = ''                    # empty for any


@dataclass
class Network:
    """A routed VLAN network on the LAN port."""
    vlan: int
    name: str
    address: str                        # the gateway's address: "10.0.40.1/24"
    isolated: bool = False
    others: list = field(default_factory=list)          # the other local subnets

    @property
    def subnet(self):
        return str(ipaddress.ip_interface(self.address).network)


@dataclass
class StaticRoute:
    destination: str                    # "192.168.5.0/24"
    gateway: str = ''                   # next hop address, empty for a blackhole route


@dataclass
class DdnsAccount:
    service: str                        # os-ddclient's name: dyndns2, noip...
    hostname: str
    username: str = ''
    password: str = ''


@dataclass
class AppBlock:
    """A traffic rule blocking apps, as the domains to block."""
    names: list                         # app names, for the description
    domains: list
    subnets: list = field(default_factory=list)         # empty for every client


@dataclass
class FirewallRule:
    """A UniFi firewall rule, with OPNsense's names for its values. Empty
    address and port lists match anything."""
    chain: str                          # LAN_IN or WAN_IN
    index: int                          # its place in the chain
    name: str
    action: str                         # pass, block or reject
    ip_version: str                     # inet, inet6 or inet46
    protocol: str = 'any'
    source: list = field(default_factory=list)          # addresses, networks or ranges
    source_ports: list = field(default_factory=list)    # "80", "1000-2000"
    destination: list = field(default_factory=list)
    destination_ports: list = field(default_factory=list)
    log: bool = False


@dataclass
class Intent:
    networks: list = field(default_factory=list)
    dhcp: list = field(default_factory=list)
    port_forwards: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)    # {(fqdn, 'A'|'AAAA'): address}
    ad_block: list = field(default_factory=list)       # subnets: ["10.0.40.0/24"]
    app_block: list = field(default_factory=list)      # AppBlock per traffic rule
    firewall_rules: list = field(default_factory=list)
    static_routes: list = field(default_factory=list)
    region_block: dict = field(default_factory=dict)   # {'countries': [...], 'direction': ...}
    mdns: list = None                   # VLANs to repeat mDNS between (0 is the LAN), None when off
    ddns: list = field(default_factory=list)


def intent_from_system_cfg(cfg):
    """Read the supported parts of a UDAPI system_cfg."""
    udapi = cfg.get('udapi', cfg)
    intent = Intent(networks=_networks_from(udapi))

    for server in udapi.get('services', {}).get('dhcpServers', []):
        if not server.get('enabled') or server.get('ipVersion', 'v4') != 'v4':
            continue
        try:
            subnet = ipaddress.ip_network(
                '%s/%s' % (server['gatewayAddress'], server['ipv4Netmask']), strict=False)
        except (KeyError, ValueError):
            logger.warning('Skipping a DHCP server without a usable subnet: %s',
                           server.get('name'))
            continue
        reservations = {}
        for lease in server.get('staticLeases', []):
            if lease.get('id') and lease.get('addresses'):
                reservations[lease['id'].lower()] = lease['addresses'][0]
        # gatewayAddress is the DHCP gateway override when one is set, and
        # the NTP servers arrive as option 42 ("a,b")
        ntp = next((o.get('value') for o in server.get('options') or [] if o.get('optionNumber') == 42), '')
        intent.dhcp.append(DhcpScope(
            subnet=str(subnet),
            range_start=server['rangeStart'],
            range_stop=server['rangeStop'],
            lease_time=int(server.get('leaseTime', 86400)),
            reservations=reservations,
            dns_servers=list(server.get('dnsServers') or []),
            router=server.get('gatewayAddress') or '',
            domain=server.get('domain') or '',
            ntp_servers=[a.strip() for a in str(ntp).split(',') if a.strip()],
        ))

    prefix = 'PortForward DNAT ['
    for rule in udapi.get('firewall/nat', []):
        description = rule.get('description', '')
        if (rule.get('chain') != 'PREROUTING' or rule.get('target') != 'DNAT'
                or not description.startswith(prefix) or not rule.get('enabled', True)):
            continue
        name = description[len(prefix):].rstrip(']')
        protocol = PROTOCOLS.get(rule.get('protocol', ''))
        destination = rule.get('destination', {})
        translation = rule.get('translation', {})
        if not protocol or not destination.get('port') or not translation.get('address'):
            logger.warning('Skipping port forward %r: unsupported shape', name)
            continue
        intent.port_forwards.append(PortForward(
            name=name,
            protocol=protocol,
            external_port=str(destination['port']),
            internal_ip=translation['address'],
            internal_port=str(translation.get('port') or destination['port']),
            source=rule.get('source', {}).get('address', ''),
        ))

    # The controller mixes its own records (unifi.<domain>, setup.ui.com, the
    # gateway's name) into hostRecords. Only records from the UI's DNS page
    # carry a ttl.
    forwarder = udapi.get('services', {}).get('dnsForwarder', {})
    for record in forwarder.get('hostRecords', []):
        address = record.get('address') or {}
        name = (record.get('hostName') or '').rstrip('.').lower()
        if 'ttl' not in record or not address.get('address') or '.' not in name or '*' in name:
            continue
        rr = 'AAAA' if address.get('version') == 'v6' else 'A'
        intent.dns_records[(name, rr)] = address['address']

    services = udapi.get('services', {})
    # Ad blocking (CyberSecure) comes as utm.dnsFilter entries with adsFilter,
    # once the gateway reports services/utm v2. netAddresses holds each
    # network's gateway address and prefix: "10.0.40.1/24".
    ad_block = set()
    for entry in services.get('utm', {}).get('dnsFilter', []):
        if entry.get('adsFilter'):
            for address in entry.get('netAddresses') or []:
                try:
                    ad_block.add(str(ipaddress.ip_interface(address).network))
                except ValueError:
                    pass
    intent.ad_block = sorted(ad_block)
    intent.app_block = _app_blocks(udapi)
    intent.firewall_rules = _firewall_rules(udapi)

    # User routes are described STATIC_ROUTE:<id>. The controller adds its own
    # (WAN default gateways, VPNs) to the same list.
    for route in udapi.get('routes/static', []):
        if not (route.get('description') or '').startswith('STATIC_ROUTE:') or not route.get('enabled', True):
            continue
        kind, destination = route.get('type'), route.get('destination')
        if kind == 'gateway' and route.get('gateway'):
            intent.static_routes.append(StaticRoute(destination, route['gateway']))
        elif kind == 'blackhole':
            intent.static_routes.append(StaticRoute(destination))
        else:
            logger.warning('Skipping static route to %s: %s routes are not supported', destination, kind)

    # Region blocking, sent only to gateways whose usg_caps has bit 6
    geoip = services.get('geoipFiltering') or {}
    if geoip.get('enabled') and geoip.get('countryList'):
        if geoip.get('action', 'block') != 'block':
            # "allow" blocks every other country, which as a floating rule
            # would also block local traffic, so it isn't mapped
            logger.warning('Skipping region blocking: only the block action is supported')
        else:
            intent.region_block = {'countries': sorted(c.upper() for c in geoip['countryList']),
                                   'direction': geoip.get('direction', 'both')}

    mdns = services.get('mdns') or {}
    if mdns.get('enabled'):
        vlans = _bridge_vlans(udapi)
        intent.mdns = sorted({vlans[i['id']] for i in mdns.get('interfaces', []) if i.get('id') in vlans})

    ddns = services.get('ddns') or {}
    if ddns.get('enabled'):
        intent.ddns = _ddns_from(ddns.get('clients', []))
    return intent


def _app_blocks(udapi):
    """UniFi traffic rules that block apps. The controller sends each as a
    filter rule per IP version with `applicationId` (or only `categoryId`
    for a whole category), a source address set and the rule's ID in
    `triggerTag`. A rule without a source covers every client."""
    sets = {s['identification']['name']: s.get('entries', []) for s in udapi.get('firewall/sets', [])}
    rules = {}
    for chain in udapi.get('firewall/filter', []):
        for rule in chain.get('rules', []):
            tag = rule.get('triggerTag') or {}
            if (tag.get('type') != 'TRAFFIC_RULE' or rule.get('target') not in ('DROP', 'REJECT')
                    or 'categoryId' not in rule):
                continue
            entry = rules.setdefault(tag.get('id'), {'apps': set(), 'subnets': set(), 'sourced': False})
            app = rule.get('applicationId')
            if app is None:
                entry['apps'].update(int(key) for key in APP_DOMAINS if int(key) >> 16 == rule['categoryId'])
            else:
                entry['apps'].update((rule['categoryId'] << 16) | a for a in (app if isinstance(app, list) else [app]))
            source = rule.get('source') or {}
            if set(source) - {'sets'}:
                logger.warning('Skipping app blocking rule %s: its source (%s) is not supported',
                               tag.get('id'), ', '.join(sorted(source)))
                entry['skip'] = True
            for name in source.get('sets', []):
                entry['sourced'] = True
                entry['subnets'].update(sets.get(name, []))
    blocks = []
    for rule_id, entry in sorted(rules.items()):
        if entry.get('skip') or (entry['sourced'] and not entry['subnets']):
            continue
        apps = [APP_DOMAINS[str(a)] for a in sorted(entry['apps']) if str(a) in APP_DOMAINS]
        if len(apps) < len(entry['apps']):
            logger.warning('App blocking rule %s: %d of its apps have no known domains and are not blocked',
                           rule_id, len(entry['apps']) - len(apps))
        if apps:
            blocks.append(AppBlock(names=sorted({a['name'] for a in apps}),
                                   domains=sorted({d for a in apps for d in a['domains']}),
                                   subnets=sorted(entry['subnets'])))
    return blocks


def _firewall_rules(udapi):
    """The rules from the UI's firewall rule lists. The controller puts them
    in the chain of their rule set (LAN_IN), among its own rules, with
    their rule index as their ID (from 20000) and a FIREWALL_RULE trigger
    tag. A rule that can't be matched in OPNsense is skipped with a
    warning, rather than applied as something wider."""
    sets = {s['identification']['name']: s for s in udapi.get('firewall/sets', [])}
    # a network as a source or destination is a set the gateway makes
    # itself: NETv4_br40 holds the network, ADDRv4_br40 the gateway's address
    for iface in udapi.get('interfaces', []):
        for address in iface.get('addresses') or []:
            if address.get('type') != 'static' or not address.get('cidr'):
                continue
            ip = ipaddress.ip_interface(address['cidr'])
            for kind, entry in (('NET', ip.network), ('ADDR', ip.ip)):
                name = '%s%s_%s' % (kind, address.get('version', 'v4'), iface['identification']['id'])
                sets.setdefault(name, {'identification': {'name': name, 'type': 'address'}, 'entries': []})
                sets[name]['entries'].append(str(entry))
    known = {'id', 'description', 'target', 'ipVersion', 'protocol', 'icmpType', 'icmpv6Type',
             'connectionState', 'source', 'destination', 'log', 'triggerTag', 'enabled'}
    rules = []
    for chain in udapi.get('firewall/filter', []):
        name = (chain.get('config') or {}).get('name')
        for rule in chain.get('rules', []):
            tag = (rule.get('triggerTag') or {}).get('type')
            if tag != 'FIREWALL_RULE':
                continue
            label = '%s rule %s (%s)' % (name, rule.get('id'), rule.get('description', ''))
            if name not in FIREWALL_CHAINS:
                logger.warning('Skipping firewall %s: only LAN In and Internet In rules are applied', label)
                continue
            if not rule.get('enabled', True):
                continue
            try:
                rules.append(_firewall_rule(name, rule, sets, known))
            except ValueError as e:
                logger.warning('Skipping firewall %s: %s', label, e)
            except LookupError:
                logger.info('Firewall %s matches nothing, so it is not applied', label)
    return sorted((r for r in rules if r), key=lambda r: (r.chain, r.index, r.ip_version))


def _firewall_rule(chain, rule, sets, known):
    """One FirewallRule, or None when OPNsense does it already. Raises
    ValueError for what can't be matched and LookupError for a rule that
    matches nothing (an empty group)."""
    if set(rule) - known:
        raise ValueError('it uses %s' % ', '.join(sorted(set(rule) - known)))
    action = FIREWALL_ACTIONS.get(rule.get('target'))
    protocol = FIREWALL_PROTOCOLS.get(rule.get('protocol') or 'all')
    if not action or not protocol:
        raise ValueError('%s %s is not supported' % (rule.get('target'), rule.get('protocol')))
    if rule.get('icmpType', 'any') != 'any' or rule.get('icmpv6Type', 'any') != 'any':
        raise ValueError('ICMP types are not supported')
    # pf keeps state, so replies already pass and invalid packets are dropped:
    # only a rule for new connections means anything
    states = set(rule.get('connectionState') or [])
    if states and 'new' not in states:
        if action == 'pass':
            return None
        raise ValueError('it only matches %s connections' % ', '.join(sorted(states)))

    def endpoint(side):
        spec = rule.get(side) or {}
        if set(spec) - {'address', 'port', 'sets'}:
            raise ValueError('its %s uses %s' % (side, ', '.join(sorted(set(spec) - {'address', 'port', 'sets'}))))
        addresses = [spec['address']] if spec.get('address') else []
        ports = [p.strip().replace(':', '-') for p in str(spec.get('port') or '').split(',') if p.strip()]
        for set_name in spec.get('sets') or []:
            found = sets.get(set_name)
            kind = (found or {}).get('identification', {}).get('type')
            if not found or kind not in ('address', 'port'):
                raise ValueError('its %s set %s is not supported' % (side, set_name))
            matches = addresses if kind == 'address' else ports
            # several matches of one kind in a rule must all match
            if matches:
                raise ValueError('its %s has more than one %s match' % (side, kind))
            entries = [str(e).replace(':', '-') if kind == 'port' else str(e) for e in found.get('entries') or []]
            if not entries:
                raise LookupError(set_name)
            matches.extend(entries)
        return addresses, ports

    source, source_ports = endpoint('source')
    destination, destination_ports = endpoint('destination')
    ip_version = {'v4only': 'inet', 'v6only': 'inet6'}.get(rule.get('ipVersion'), 'inet46')
    families = {':' in a for a in source + destination}
    if ip_version == 'inet46' and len(families) == 1:
        ip_version = 'inet6' if families == {True} else 'inet'
    return FirewallRule(chain=chain, index=int(rule['id']), name=rule.get('description') or '',
                        action=action, ip_version=ip_version, protocol=protocol,
                        source=source, source_ports=source_ports, destination=destination,
                        destination_ports=destination_ports, log=bool(rule.get('log')))


def _bridge_vlans(udapi):
    """The VLAN of each bridge on the LAN port ({'br0': 0, 'br40': 40}), 0 for
    the untagged LAN."""
    tags = {LAN_PORT: 0}
    for iface in udapi.get('interfaces', []):
        vlan = iface.get('vlan') or {}
        if (iface.get('identification', {}).get('type') == 'vlan'
                and (vlan.get('interface') or {}).get('id') == LAN_PORT):
            tags[iface['identification']['id']] = vlan['id']
    bridges = {}
    for iface in udapi.get('interfaces', []):
        if iface.get('identification', {}).get('type') == 'bridge':
            members = [tags[m['id']] for m in (iface.get('bridge') or {}).get('interfaces', [])
                       if m.get('id') in tags]
            if len(members) == 1:
                bridges[iface['identification']['id']] = int(members[0])
    return bridges


def _ddns_from(clients):
    """os-ddclient accounts from UniFi's services.ddns clients. The
    controller sends "unknown" or "emptyString" for an empty field."""
    def value(client, key):
        text = client.get(key) or ''
        return '' if text in ('unknown', 'emptyString') else text

    accounts = []
    for client in clients:
        service = DDNS_SERVICES.get(client.get('service'))
        # Namecheap goes out as a custom service named namecheap.<n>, with
        # the domain as its username
        if client.get('service') == 'custom' and (client.get('customName') or '').startswith('namecheap.'):
            service = 'namecheap'
        if not service or not value(client, 'hostname'):
            logger.warning('Skipping Dynamic DNS for %s: service %s is not supported',
                           client.get('hostname'), client.get('customName') or client.get('service'))
            continue
        accounts.append(DdnsAccount(service, value(client, 'hostname'),
                                    value(client, 'username'), value(client, 'password')))
    return accounts


def _networks_from(udapi):
    """A UXG carries each VLAN network on a bridge (br40) over a VLAN
    interface on the LAN port (eth1.40). VLAN-only networks have no address
    and are left alone, since the gateway doesn't route them."""
    interfaces = udapi.get('interfaces', [])
    vlans = _bridge_vlans(udapi)

    # the network's name is only in its DHCP server's: net_IoT_br40_10-0-40-0-24
    names = {}
    for server in udapi.get('services', {}).get('dhcpServers', []):
        match = re.match(r'net_(.+)_(br\d+)_', server.get('name') or '')
        if match:
            names[match.group(2)] = match.group(1)
    sets = {s.get('identification', {}).get('name'): s.get('entries') or []
            for s in udapi.get('firewall/sets', [])}

    networks = []
    for iface in interfaces:
        ident = iface.get('identification', {})
        vlan = vlans.get(ident.get('id')) if ident.get('type') == 'bridge' else None
        address = next((a['cidr'] for a in iface.get('addresses') or []
                        if a.get('version') == 'v4' and a.get('type') == 'static' and a.get('cidr')),
                       None)
        # the untagged LAN (VLAN 0) is OPNsense's own LAN
        if not vlan or not address:
            continue
        network = Network(vlan=vlan, address=address, name=names.get(ident['id']) or 'VLAN%s' % vlan)
        network.isolated = network.subnet in sets.get('isolated_subnets', [])
        network.others = sorted(n for n in sets.get('local_network', []) if n != network.subnet)
        networks.append(network)
    return sorted(networks, key=lambda n: n.vlan)


# ── Making OPNsense match ────────────────────────────────────────────────

def _owned(description):
    return (description or '').startswith(OWNER_TAG)


def _selected(value):
    """The chosen keys of a multi-select field: GETs of a model return
    {key: {value, selected}}, searches a comma-separated string."""
    if isinstance(value, dict):
        return [key for key, option in value.items() if isinstance(option, dict) and option.get('selected')]
    return [item for item in (value or '').split(',') if item]


class Reconciler:
    """Plans and applies the changes that make OPNsense match an Intent.

    `api` is an OPNsenseAPI (get/post). Every change is one OPNsense API call,
    logged as it is planned; services are reloaded once at the end."""

    def __init__(self, api, mode='plan'):
        if mode not in MODES:
            raise ValueError('apply mode must be one of %s' % ', '.join(MODES))
        self.api = api
        self.mode = mode

    def run(self, intent):
        """Reconcile once. Returns the list of changes as text."""
        if self.mode == 'off':
            return []
        changes, reload = [], []
        try:
            # new networks first and old ones last, so nothing is removed
            # while a Kea subnet or rule still refers to it
            ifaces, removals = self._networks(intent.networks, changes)
            steps = (
                (lambda: self._kea(intent.dhcp, intent.networks, ifaces, removals, changes),
                 ('/api/kea/service/reconfigure',)),
                (lambda: self._rules(intent.networks, ifaces, changes), ('/api/firewall/filter/apply',)),
                (lambda: self._firewall(intent.firewall_rules, ifaces, changes),
                 ('/api/firewall/alias/reconfigure', '/api/firewall/filter/apply')),
                (lambda: self._port_forwards(intent.port_forwards, changes), ('/api/firewall/d_nat/apply',)),
                (lambda: self._dns_records(intent.dns_records, changes), ('/api/unbound/service/reconfigure',)),
                (lambda: self._ad_block(intent.ad_block, changes), ('/api/unbound/service/dnsbl',)),
                (lambda: self._app_block(intent.app_block, changes), ('/api/unbound/service/dnsbl',)),
                (lambda: self._static_routes(intent.static_routes, changes), ('/api/routes/routes/reconfigure',)),
                (lambda: self._mdns(intent.mdns, ifaces, changes), ('/api/mdnsrepeater/service/reconfigure',)),
                (lambda: self._ddns(intent.ddns, changes), ('/api/dyndns/service/reconfigure',)),
                # last, since its NAT and filter rules are the least proven
                (lambda: self._region_block(intent.region_block, changes),
                 ('/api/firewall/alias/reconfigure', '/api/firewall/filter/apply')),
            )
            for step, apply_paths in steps:
                if step():
                    reload += [path for path in apply_paths if path not in reload]
        except Exception:
            # what was saved before the failure still gets applied, since the
            # next run will find it saved and see nothing to do
            self._reload(reload)
            self._log(changes)
            raise
        self._reload(reload)
        self._remove_networks(removals, changes)
        self._log(changes)
        return changes

    def _reload(self, paths):
        for path in paths:
            self._post(path)

    def _log(self, changes):
        for text in changes:
            logger.info('%s: %s', 'Applied' if self.mode == 'apply' else 'Would apply', text)
        if not changes:
            logger.debug('OPNsense already matches the controller')

    def _post(self, path, body=None):
        if self.mode != 'apply':
            return {}
        response = self.api.post(path, body or {})
        if isinstance(response, dict) and response.get('result') == 'failed':
            raise RuntimeError('%s failed: %s' % (path, response.get('validations')))
        return response

    def _plugin_get(self, path, plugin, wanted):
        """GET a plugin's endpoint, or None when the plugin isn't installed
        (OPNsense answers 404). Plugins are never installed from here."""
        try:
            return self.api.get(path)
        except Exception as e:
            if getattr(e, 'status', None) != 404:
                raise
            if wanted:
                logger.warning('%s is not installed in OPNsense, so this UniFi setting is not applied', plugin)
            return None

    # VLANs and interfaces

    def _networks(self, networks, changes):
        """Creates and updates the VLAN and interface of each network. Returns
        the interface of each VLAN ({40: 'opt1'}, None for one only planned)
        and the owned VLANs UniFi no longer has, as (vlan row, interface row)."""
        assigned = self.api.get('/api/interfaces/assignment/search_item').get('rows', [])
        lan = next((row for row in assigned if row.get('identifier') == 'lan'), None)
        if not lan:
            return {}, []
        vlan_rows = [row for row in self.api.get('/api/interfaces/vlan_settings/search_item').get('rows', [])
                     if row.get('if') == lan['if']]
        by_tag = {int(row['tag']): row for row in vlan_rows}

        added = False
        for network in networks:
            if network.vlan not in by_tag:
                changes.append('VLAN %d (%s) on %s: add' % (network.vlan, network.name, lan['if']))
                self._post('/api/interfaces/vlan_settings/add_item', {'vlan': {
                    'if': lan['if'], 'tag': str(network.vlan), 'pcp': '0',
                    'descr': '%s %s' % (OWNER_TAG, network.name)}})
                added = True
            elif (_owned(by_tag[network.vlan].get('descr'))
                    and by_tag[network.vlan]['descr'] != '%s %s' % (OWNER_TAG, network.name)):
                changes.append('VLAN %d: rename to %s' % (network.vlan, network.name))
                self._post('/api/interfaces/vlan_settings/set_item/' + by_tag[network.vlan]['uuid'],
                           {'vlan': {'descr': '%s %s' % (OWNER_TAG, network.name)}})
        if added and self.mode == 'apply':
            self._post('/api/interfaces/vlan_settings/reconfigure')
            vlan_rows = [row for row in self.api.get('/api/interfaces/vlan_settings/search_item').get('rows', [])
                         if row.get('if') == lan['if']]
            by_tag = {int(row['tag']): row for row in vlan_rows}

        # once assigned, a VLAN's device reads "vlan01 [IoT]"
        def device(vlan):
            return (by_tag.get(vlan, {}).get('vlanif') or '').split(' ')[0] or None

        by_device = {row.get('if'): row for row in assigned}
        changed = False
        for network in networks:
            device_name = device(network.vlan)
            current = by_device.get(device_name) if device_name else None
            descr = re.sub(r'[^A-Za-z0-9_]', '_', network.name)[:32]
            if current is None:
                changes.append('Interface %s on VLAN %d: add' % (network.address, network.vlan))
                self._post('/api/interfaces/assignment/add_item', {'interface': {
                    'if': device_name or '', 'descr': descr, 'enable': '1',
                    'type4': 'staticv4', 'ipaddr': network.address}})
                changed = True
            elif current.get('ipaddr') != network.address or current.get('enable') != '1':
                changes.append('Interface %s: %s -> %s' % (current['identifier'], current.get('ipaddr'),
                                                            network.address))
                self._post('/api/interfaces/assignment/set_item/' + current['uuid'],
                           {'interface': {'ipaddr': network.address, 'enable': '1'}})
                changed = True
        if changed and self.mode == 'apply':
            self._post('/api/interfaces/assignment/reconfigure')
            assigned = self.api.get('/api/interfaces/assignment/search_item').get('rows', [])
            by_device = {row.get('if'): row for row in assigned}

        ifaces = {}
        for network in networks:
            row = by_device.get(device(network.vlan))
            ifaces[network.vlan] = row['identifier'] if row else None
        wanted = {network.vlan for network in networks}
        removals = [(row, by_device.get(device(tag))) for tag, row in sorted(by_tag.items())
                    if tag not in wanted and _owned(row.get('descr'))]
        return ifaces, removals

    def _remove_networks(self, removals, changes):
        for vlan, iface in removals:
            if iface:
                changes.append('Interface %s on VLAN %s: remove' % (iface['identifier'], vlan['tag']))
                # new interfaces are locked, and OPNsense won't remove a locked one
                self._post('/api/interfaces/assignment/set_item/' + iface['uuid'], {'interface': {'lock': '0'}})
                self._post('/api/interfaces/assignment/del_item/' + iface['uuid'])
        if any(iface for _, iface in removals):
            self._post('/api/interfaces/assignment/reconfigure')
        for vlan, _ in removals:
            changes.append('VLAN %s (%s): remove' % (vlan['tag'], vlan['descr'][len(OWNER_TAG):].strip()))
            self._post('/api/interfaces/vlan_settings/del_item/' + vlan['uuid'])
        if removals:
            self._post('/api/interfaces/vlan_settings/reconfigure')

    # Firewall rules for networks

    @staticmethod
    def _rules_for(network, iface):
        """A network's rules by kind: one passing its traffic and, when it is
        isolated, one ahead of it for each other local network, blocking it.
        OPNsense rules made through the API take a single network."""
        def rule(action, destination, sequence, description):
            return {
                'enabled': '1', 'action': action, 'quick': '1', 'direction': 'in',
                'interface': iface, 'ipprotocol': 'inet', 'source_net': iface,
                'destination_net': destination, 'destination_not': '0',
                'sequence': str(RULE_SEQUENCE + 2 * network.vlan + sequence),
                'description': '%s VLAN %d%s: %s' % (OWNER_TAG, network.vlan, description, network.name),
            }
        rules = {'pass': rule('pass', 'any', 1, '')}
        if network.isolated:
            for other in network.others:
                rules[other] = rule('block', other, 0, ' to %s blocked' % other)
        return rules

    def _rules(self, networks, ifaces, changes):
        before = len(changes)
        owned = {}
        for row in self.api.get('/api/firewall/filter/search_rule').get('rows', []):
            match = re.match(re.escape(OWNER_TAG) + r' VLAN (\d+)(?: to (\S+) blocked)?:', row.get('description') or '')
            if match:
                owned[(int(match.group(1)), match.group(2) or 'pass')] = row
        wanted = set()
        for network in networks:
            for kind, want in sorted(self._rules_for(network, ifaces.get(network.vlan) or '').items()):
                wanted.add((network.vlan, kind))
                current = owned.get((network.vlan, kind))
                if current is None:
                    changes.append('Rule %r: add' % want['description'])
                    self._post('/api/firewall/filter/add_rule', {'rule': want})
                elif any(current.get(key) != want[key] for key in
                         ('description', 'action', 'source_net', 'destination_net', 'sequence')):
                    changes.append('Rule %r: update' % want['description'])
                    self._post('/api/firewall/filter/set_rule/' + current['uuid'], {'rule': want})
        for key, current in sorted(owned.items()):
            if key not in wanted:
                changes.append('Rule %r: remove' % current['description'])
                self._post('/api/firewall/filter/del_rule/' + current['uuid'])
        return len(changes) > before

    # Firewall rules from the UI

    @staticmethod
    def _firewall_plan(rules, ifaces):
        """The OPNsense rules for UniFi's firewall rules, by description, and
        the aliases they need, by name. A rule field holds one address or
        port, so lists and address ranges go in an alias named after its
        contents. A rule to any destination leaves out the firewall itself,
        because UniFi's LAN In and Internet In don't cover traffic to the
        gateway (that is LAN Local and Internet Local)."""
        lan = ','.join(['lan'] + sorted(i for i in ifaces.values() if i))
        aliases = {}

        def field(values, kind):
            if not values:
                return 'any' if kind == 'network' else ''
            if len(values) == 1 and (kind == 'port' or '-' not in values[0]):
                return values[0]
            content = '\n'.join(sorted(v.replace('-', ':') if kind == 'port' else v for v in values))
            name = FIREWALL_ALIAS + hashlib.sha256((kind + content).encode()).hexdigest()[:12]
            aliases[name] = {'enabled': '1', 'name': name, 'type': kind, 'content': content,
                             'description': '%s rule %ss' % (FIREWALL_DESCR, 'address' if kind == 'network' else kind)}
            return name

        wanted = {}
        for position, rule in enumerate(rules):
            chain = rule.chain.replace('_', 'v6_') if rule.ip_version == 'inet6' else rule.chain
            description = '%s %s %d: %s' % (FIREWALL_DESCR, chain, rule.index, rule.name)
            destination = field(rule.destination, 'network')
            wanted[description] = {
                'enabled': '1', 'action': rule.action, 'quick': '1', 'direction': 'in',
                'interface': lan if FIREWALL_CHAINS[rule.chain] == 'lan' else 'wan',
                'ipprotocol': rule.ip_version, 'protocol': rule.protocol,
                'source_net': field(rule.source, 'network'), 'source_not': '0',
                'source_port': field(rule.source_ports, 'port'),
                'destination_net': '(self)' if destination == 'any' else destination,
                'destination_not': '1' if destination == 'any' else '0',
                'destination_port': field(rule.destination_ports, 'port'),
                'log': '1' if rule.log else '0', 'sequence': str(FIREWALL_SEQUENCE + position),
                'description': description,
            }
        return wanted, aliases

    def _firewall(self, rules, ifaces, changes):
        before = len(changes)
        wanted, aliases = self._firewall_plan(rules, ifaces)
        owned = {row['description']: row for row in self.api.get('/api/firewall/filter/search_rule').get('rows', [])
                 if (row.get('description') or '').startswith(FIREWALL_DESCR + ' ')}
        if not wanted and not owned:
            return False
        current_aliases = {row['name']: row for row in self.api.get('/api/firewall/alias/search_item').get('rows', [])
                           if (row.get('name') or '').startswith(FIREWALL_ALIAS)}

        # aliases first, then the rules using them, then old aliases
        for name, alias in sorted(aliases.items()):
            if name not in current_aliases:
                changes.append('Firewall alias %s (%s): add' % (name, alias['content'].replace('\n', ', ')))
                self._post('/api/firewall/alias/add_item', {'alias': alias})

        def same(current, want):
            # searches show the protocol in its own case and multiple
            # interfaces in any order
            def norm(key, value):
                value = str(value or '').lower()
                return ','.join(sorted(value.split(','))) if key == 'interface' else value
            return all(norm(key, current.get(key)) == norm(key, value) for key, value in want.items())

        for description, want in sorted(wanted.items(), key=lambda item: int(item[1]['sequence'])):
            current = owned.pop(description, None)
            if current is None:
                changes.append('Rule %r: add' % description)
                self._post('/api/firewall/filter/add_rule', {'rule': want})
            elif not same(current, want):
                changes.append('Rule %r: update' % description)
                self._post('/api/firewall/filter/set_rule/' + current['uuid'], {'rule': want})
        for description, current in sorted(owned.items()):
            changes.append('Rule %r: remove' % description)
            self._post('/api/firewall/filter/del_rule/' + current['uuid'])
        for name, current in sorted(current_aliases.items()):
            if name not in aliases:
                changes.append('Firewall alias %s: remove' % name)
                self._post('/api/firewall/alias/del_item/' + current['uuid'])
        return len(changes) > before

    # Kea DHCPv4

    def _kea(self, scopes, networks, ifaces, removals, changes):
        before = len(changes)
        managed = {network.subnet: network for network in networks}
        if not scopes and not managed and not removals:
            return False
        subnets = {row['subnet']: row for row in
                   self.api.get('/api/kea/dhcpv4/search_subnet').get('rows', [])}
        reservations = self.api.get('/api/kea/dhcpv4/search_reservation').get('rows', [])
        # a subnet without its own lease time uses the global one
        general = self.api.get('/api/kea/dhcpv4/get').get('dhcpv4', {}).get('general', {})
        default_lease = str(general.get('valid_lifetime') or '')

        # Kea only serves the interfaces it listens on
        listening = _selected(general.get('interfaces'))
        serving = [ifaces.get(managed[scope.subnet].vlan) for scope in scopes if scope.subnet in managed]
        serving = [iface for iface in serving if iface]
        # drop removed networks and managed ones whose DHCP is off
        drop = {iface['identifier'] for _, iface in removals if iface}
        drop |= {iface for iface in ifaces.values() if iface and iface not in serving}
        want = [i for i in listening if i not in drop]
        want += [i for i in serving if i not in want]
        if want != list(listening):
            changes.append('Kea interfaces: %s -> %s' % (','.join(listening), ','.join(want)))
            self._post('/api/kea/dhcpv4/set', {'dhcpv4': {'general': {'interfaces': ','.join(want)}}})

        for scope in scopes:
            subnet = subnets.get(scope.subnet)
            options = self._dhcp_options(scope, managed.get(scope.subnet))
            if not subnet and scope.subnet in managed:
                name = managed[scope.subnet].name
                changes.append('Kea subnet %s (%s): add' % (scope.subnet, name))
                result = self._post('/api/kea/dhcpv4/add_subnet', {'subnet4': {
                    'subnet': scope.subnet,
                    'pools': '%s - %s' % (scope.range_start, scope.range_stop),
                    'valid_lifetime': str(scope.lease_time),
                    'option_data_autocollect': '0',
                    'option_data': options,
                    'description': '%s %s' % (OWNER_TAG, name)}})
                if not result.get('uuid'):
                    continue        # only planned: its reservations come once it exists
                subnet = {'uuid': result['uuid'], 'subnet': scope.subnet, 'valid_lifetime': str(scope.lease_time),
                          'pools': '%s - %s' % (scope.range_start, scope.range_stop)}
                subnet.update(('option_data.' + key, value) for key, value in options.items())
            if not subnet:
                logger.warning('No Kea subnet for %s: create it in OPNsense first', scope.subnet)
                continue
            uuid = subnet['uuid']

            pool = '%s - %s' % (scope.range_start, scope.range_stop)
            update = {}
            if subnet.get('pools', '').strip() != pool:
                update['pools'] = pool
            if str(subnet.get('valid_lifetime') or default_lease) != str(scope.lease_time):
                update['valid_lifetime'] = str(scope.lease_time)
            if any((subnet.get('option_data.' + key) or '') != value for key, value in options.items()):
                update['option_data_autocollect'] = '0'
                update['option_data'] = options
            if update:
                changes.append('Kea subnet %s: set %s' % (scope.subnet, update))
                self._post('/api/kea/dhcpv4/set_subnet/' + uuid, {'subnet4': update})

            mine = [r for r in reservations if r.get('subnet') == uuid]
            by_mac = {r['hw_address'].lower(): r for r in mine if r.get('hw_address')}
            network = ipaddress.ip_network(scope.subnet)
            for mac, ip in sorted(scope.reservations.items()):
                if ipaddress.ip_address(ip) not in network:
                    logger.warning('Skipping reservation %s -> %s: not in %s', mac, ip, scope.subnet)
                    continue
                current = by_mac.get(mac)
                if current is None:
                    changes.append('Kea reservation %s -> %s: add' % (mac, ip))
                    self._post('/api/kea/dhcpv4/add_reservation', {'reservation': {
                        'subnet': uuid, 'hw_address': mac, 'ip_address': ip,
                        'description': OWNER_TAG + ' fixed IP from UniFi'}})
                elif current.get('ip_address') != ip:
                    changes.append('Kea reservation %s: %s -> %s' % (mac, current.get('ip_address'), ip))
                    self._post('/api/kea/dhcpv4/set_reservation/' + current['uuid'],
                               {'reservation': {'ip_address': ip}})
            for mac, current in sorted(by_mac.items()):
                if mac not in scope.reservations and _owned(current.get('description')):
                    changes.append('Kea reservation %s -> %s: remove' % (mac, current.get('ip_address')))
                    self._post('/api/kea/dhcpv4/del_reservation/' + current['uuid'])

        wanted = {scope.subnet for scope in scopes}
        for cidr, subnet in sorted(subnets.items()):
            if cidr not in wanted and _owned(subnet.get('description')):
                for reservation in reservations:
                    if reservation.get('subnet') == subnet['uuid']:
                        changes.append('Kea reservation %s -> %s: remove' % (
                            reservation.get('hw_address'), reservation.get('ip_address')))
                        self._post('/api/kea/dhcpv4/del_reservation/' + reservation['uuid'])
                changes.append('Kea subnet %s: remove' % cidr)
                self._post('/api/kea/dhcpv4/del_subnet/' + subnet['uuid'])
        return len(changes) > before

    @staticmethod
    def _dhcp_options(scope, network):
        """The Kea options a scope wants. A subnet the reconciler made gets
        exactly UniFi's options, since Kea's autocollect doesn't fill in one
        made through the API. A hand-made one only gets what UniFi sets, so
        an NTP server or domain added in OPNsense stays until UniFi sets
        its own. Setting any turns autocollect off for the subnet."""
        if network:
            router = scope.router or str(ipaddress.ip_interface(network.address).ip)
            return {'routers': router,
                    'domain_name_servers': ','.join(scope.dns_servers) or router,
                    'ntp_servers': ','.join(scope.ntp_servers),
                    'domain_name': scope.domain}
        options = {'routers': scope.router, 'domain_name_servers': ','.join(scope.dns_servers),
                   'ntp_servers': ','.join(scope.ntp_servers), 'domain_name': scope.domain}
        return {key: value for key, value in options.items() if value}

    # Destination NAT

    @staticmethod
    def _nat_rule(forward):
        return {
            'disabled': '0',
            'interface': 'wan',
            'ipprotocol': 'inet',
            'protocol': forward.protocol,
            'source': {'network': forward.source or 'any', 'port': '', 'not': '0'},
            'destination': {'network': 'wanip', 'port': forward.external_port, 'not': '0'},
            'target': forward.internal_ip,
            'local-port': forward.internal_port,
            'pass': 'pass',
            'descr': '%s %s' % (OWNER_TAG, forward.name),
        }

    @staticmethod
    def _nat_matches(row, want):
        return (row.get('protocol') == want['protocol']
                and row.get('destination.port') == want['destination']['port']
                and row.get('target') == want['target']
                and row.get('local-port') == want['local-port']
                and (row.get('source.network') or 'any') == want['source']['network']
                and row.get('disabled') == '0')

    def _port_forwards(self, forwards, changes):
        before = len(changes)
        rows = self.api.get('/api/firewall/d_nat/search_rule').get('rows', [])
        # the region blocking rule is _region_block's
        owned = {row['descr'][len(OWNER_TAG):].strip(): row for row in rows
                 if _owned(row.get('descr')) and not row['descr'].startswith(REGION_DESCR)}
        wanted = {forward.name: forward for forward in forwards}

        for name, forward in sorted(wanted.items()):
            rule = self._nat_rule(forward)
            current = owned.get(name)
            summary = '%s %s -> %s:%s%s' % (
                forward.protocol, forward.external_port, forward.internal_ip,
                forward.internal_port, ' from ' + forward.source if forward.source else '')
            if current is None:
                changes.append('Port forward %r (%s): add' % (name, summary))
                self._post('/api/firewall/d_nat/add_rule', {'rule': rule})
            elif not self._nat_matches(current, rule):
                changes.append('Port forward %r (%s): update' % (name, summary))
                self._post('/api/firewall/d_nat/set_rule/' + current['uuid'], {'rule': rule})
        for name, current in sorted(owned.items()):
            if name not in wanted:
                changes.append('Port forward %r: remove' % name)
                self._post('/api/firewall/d_nat/del_rule/' + current['uuid'])
        return len(changes) > before

    # Unbound host overrides

    def _dns_records(self, records, changes):
        before = len(changes)
        rows = self.api.get('/api/unbound/settings/search_host_override').get('rows', [])
        existing = {}
        for row in rows:
            fqdn = '%s.%s' % (row.get('hostname', ''), row.get('domain', ''))
            existing.setdefault((fqdn.strip('.').lower(), row.get('rr', 'A')), row)

        for (fqdn, rr), address in sorted(records.items()):
            current = existing.get((fqdn, rr))
            if current is None:
                hostname, _, domain = fqdn.partition('.')
                changes.append('DNS %s %s -> %s: add' % (rr, fqdn, address))
                self._post('/api/unbound/settings/add_host_override', {'host': {
                    'enabled': '1', 'hostname': hostname, 'domain': domain, 'rr': rr,
                    'server': address, 'description': OWNER_TAG + ' DNS record from UniFi'}})
            elif current.get('server') != address or current.get('enabled') != '1':
                changes.append('DNS %s %s: %s -> %s' % (rr, fqdn, current.get('server'), address))
                self._post('/api/unbound/settings/set_host_override/' + current['uuid'],
                           {'host': {'server': address, 'enabled': '1'}})
        for key, current in sorted(existing.items()):
            if key not in records and _owned(current.get('description')):
                changes.append('DNS %s %s: remove' % (key[1], key[0]))
                self._post('/api/unbound/settings/del_host_override/' + current['uuid'])
        return len(changes) > before

    # Unbound blocklist for ad blocking

    def _ad_block(self, subnets, changes):
        """One blocklist covering every network UniFi blocks ads on. Its
        description lists the networks, so a change shows there."""
        before = len(changes)
        owned = [row for row in self.api.get('/api/unbound/settings/search_dnsbl').get('rows', [])
                 if (row.get('description') or '').startswith(OWNER_TAG + ' Ad blocking')]
        if subnets:
            description = '%s Ad blocking for %s' % (OWNER_TAG, ', '.join(subnets))
            body = {'blocklist': {'enabled': '1', 'type': AD_BLOCKLISTS, 'source_nets': ','.join(subnets),
                                  'description': description}}
            current = owned.pop(0) if owned else None
            if current is None:
                changes.append('Ad blocking for %s: add' % ', '.join(subnets))
                self._post('/api/unbound/settings/add_dnsbl', body)
            elif current.get('description') != description or current.get('enabled') != '1':
                changes.append('Ad blocking: now for %s' % ', '.join(subnets))
                self._post('/api/unbound/settings/set_dnsbl/' + current['uuid'], body)
        for current in owned:
            changes.append('Blocklist %r: remove' % current['description'])
            self._post('/api/unbound/settings/del_dnsbl/' + current['uuid'])
        return len(changes) > before

    # Unbound blocklists for app blocking

    def _app_block(self, blocks, changes):
        """One blocklist per traffic rule, blocking its apps' domains and
        their subdomains for the rule's networks. The description ends with
        a hash of the domains and networks, so a changed rule is replaced."""
        before = len(changes)
        prefix = OWNER_TAG + ' App blocking'
        owned = {row.get('description'): row for row in self.api.get('/api/unbound/settings/search_dnsbl').get('rows', [])
                 if (row.get('description') or '').startswith(prefix)}
        for block in blocks:
            digest = hashlib.sha256(json.dumps([block.domains, block.subnets]).encode()).hexdigest()[:8]
            label = '%s for %s' % (', '.join(block.names), ', '.join(block.subnets) or 'all networks')
            description = '%s: %s (%s)' % (prefix, label[:180], digest)
            if owned.pop(description, None) is not None:
                continue
            changes.append('App blocking: %s: add' % label)
            self._post('/api/unbound/settings/add_dnsbl', {'blocklist': {
                'enabled': '1', 'wildcards': ','.join(block.domains),
                'source_nets': ','.join(block.subnets), 'description': description}})
        for description, current in sorted(owned.items()):
            changes.append('Blocklist %r: remove' % description)
            self._post('/api/unbound/settings/del_dnsbl/' + current['uuid'])
        return len(changes) > before

    # Static routes

    def _static_routes(self, routes, changes):
        """Routes go through the OPNsense gateway with the next hop's address,
        and one is added (described OWNER_TAG) when there is none. Blackhole
        routes use OPNsense's Null4/Null6 gateways. A hand-made route to the
        same network is updated, like a hand-made reservation."""
        before = len(changes)
        rows = self.api.get('/api/routes/routes/search_route').get('rows', [])
        gateways = self.api.get('/api/routing/settings/search_gateway').get('rows', [])
        by_address = {(row.get('gateway'), row.get('ipprotocol')): row['name']
                      for row in gateways if row.get('gateway') and row.get('name')}
        assigned = None

        wanted, added = {}, False
        for route in routes:
            family = 'inet6' if ':' in route.destination else 'inet'
            if not route.gateway:
                wanted[route.destination] = 'Null6' if family == 'inet6' else 'Null4'
                continue
            name = by_address.get((route.gateway, family))
            if not name:
                if assigned is None:
                    assigned = self.api.get('/api/interfaces/assignment/search_item').get('rows', [])
                iface = _interface_for(route.gateway, assigned)
                if not iface:
                    logger.warning('Skipping static route to %s: no interface has %s in its subnet',
                                   route.destination, route.gateway)
                    continue
                name = ('UNIFI_' + re.sub(r'[^0-9A-Za-z]', '_', route.gateway))[:32]
                changes.append('Gateway %s (%s on %s): add' % (name, route.gateway, iface))
                self._post('/api/routing/settings/add_gateway', {'gateway_item': {
                    'name': name, 'interface': iface, 'ipprotocol': family, 'gateway': route.gateway,
                    'defaultgw': '0', 'monitor_disable': '1', 'disabled': '0',
                    'descr': OWNER_TAG + ' next hop of static routes from UniFi'}})
                by_address[(route.gateway, family)] = name
                added = True
            wanted[route.destination] = name
        if added and self.mode == 'apply':
            self._post('/api/routing/settings/reconfigure')

        existing = {row.get('network'): row for row in rows}
        for destination, gateway in sorted(wanted.items()):
            current = existing.get(destination)
            if current is None:
                changes.append('Static route %s via %s: add' % (destination, gateway))
                self._post('/api/routes/routes/add_route', {'route': {
                    'network': destination, 'gateway': gateway, 'enabled': '1',
                    'descr': OWNER_TAG + ' static route from UniFi'}})
            elif current.get('gateway') != gateway or current.get('enabled', '1') != '1':
                changes.append('Static route %s: via %s -> %s' % (destination, current.get('gateway'), gateway))
                self._post('/api/routes/routes/set_route/' + current['uuid'],
                           {'route': {'gateway': gateway, 'enabled': '1'}})
        kept = set(wanted.values())
        for destination, current in sorted(existing.items()):
            if destination in wanted:
                continue
            if _owned(current.get('descr')):
                changes.append('Static route %s: remove' % destination)
                self._post('/api/routes/routes/del_route/' + current['uuid'])
            else:
                kept.add(current.get('gateway'))

        # the gateways the reconciler added go once no route uses them
        removed = False
        for row in gateways:
            if _owned(row.get('descr')) and row.get('name') not in kept:
                changes.append('Gateway %s: remove' % row['name'])
                self._post('/api/routing/settings/del_gateway/' + row['uuid'])
                removed = True
        if removed:
            self._post('/api/routing/settings/reconfigure')
        return len(changes) > before

    # mDNS reflection (os-mdns-repeater)

    def _mdns(self, vlans, ifaces, changes):
        """os-mdns-repeater has one setting for the whole router, so UniFi
        decides it: on between the networks UniFi names (two at least), off
        otherwise. UniFi's service filter (reflectFilter) has no equivalent,
        so every service is repeated."""
        interfaces = []
        for vlan in vlans or []:
            iface = 'lan' if vlan == 0 else ifaces.get(vlan)
            if iface and iface not in interfaces:
                interfaces.append(iface)
        settings = self._plugin_get('/api/mdnsrepeater/settings/get', 'os-mdns-repeater (for mDNS)',
                                    len(interfaces) > 1)
        if settings is None:
            return False
        current = settings.get('mdnsrepeater', {})
        enabled = '1' if len(interfaces) > 1 else '0'
        want = {'enabled': enabled}
        if enabled == '1':
            want['interfaces'] = ','.join(sorted(interfaces))
        if (current.get('enabled') == enabled
                and (enabled == '0' or sorted(_selected(current.get('interfaces'))) == sorted(interfaces))):
            return False
        changes.append('mDNS repeater: %s' % ('on for ' + want['interfaces'] if enabled == '1' else 'off'))
        self._post('/api/mdnsrepeater/settings/set', {'mdnsrepeater': want})
        return True

    # Dynamic DNS (os-ddclient)

    @staticmethod
    def _ddns_account(account):
        """An os-ddclient account. Its password can't be read back, so the
        description ends in a hash of the fields, and a change to any of them
        changes the description."""
        fields = {'enabled': '1', 'service': account.service, 'hostnames': account.hostname,
                  'username': account.username, 'password': account.password,
                  # a web check finds the public address even behind another NAT
                  'checkip': 'web_icanhazip'}
        digest = hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()[:8]
        fields['description'] = '%s DDNS %s %s #%s' % (OWNER_TAG, account.service, account.hostname, digest)
        return fields

    def _ddns(self, accounts, changes):
        before = len(changes)
        result = self._plugin_get('/api/dyndns/accounts/search_item', 'os-ddclient (for Dynamic DNS)',
                                  bool(accounts))
        if result is None:
            return False
        owned = {row['description'].rsplit(' #', 1)[0]: row
                 for row in result.get('rows', []) if _owned(row.get('description'))}
        wanted = {}
        for account in accounts:
            fields = self._ddns_account(account)
            wanted[fields['description'].rsplit(' #', 1)[0]] = (account, fields)

        for key, (account, fields) in sorted(wanted.items()):
            current = owned.get(key)
            if current is None:
                changes.append('DDNS %s %s: add' % (account.service, account.hostname))
                self._post('/api/dyndns/accounts/add_item', {'account': fields})
            elif current.get('description') != fields['description'] or current.get('enabled') != '1':
                changes.append('DDNS %s %s: update' % (account.service, account.hostname))
                self._post('/api/dyndns/accounts/set_item/' + current['uuid'], {'account': fields})
        for key, current in sorted(owned.items()):
            if key not in wanted:
                changes.append('%s: remove' % key[len(OWNER_TAG):].strip())
                self._post('/api/dyndns/accounts/del_item/' + current['uuid'])

        if accounts:
            general = self.api.get('/api/dyndns/settings/get').get('ddclient', {}).get('general', {})
            if general.get('enabled') != '1':
                changes.append('Dynamic DNS service: enable')
                self._post('/api/dyndns/settings/set', {'ddclient': {'general': {'enabled': '1'}}})
        return len(changes) > before

    # Region blocking (GeoIP)

    @staticmethod
    def _region_rules(direction):
        """Floating block rules (on every interface, ahead of interface rules)
        and, for incoming traffic, a "no RDR" rule ahead of the port forwards:
        they use "rdr pass", which skips the filter rules. The rules log what
        they block, so it shows as blocked flows in UniFi."""
        def rule(source, destination, which):
            return {'enabled': '1', 'action': 'block', 'quick': '1', 'log': '1', 'direction': 'in',
                    'interface': '', 'ipprotocol': 'inet46', 'source_net': source,
                    'destination_net': destination, 'sequence': '1',
                    'description': '%s %s' % (REGION_DESCR, which)}
        rules, nat = {}, None
        if direction in ('incoming', 'both'):
            rules['incoming'] = rule(REGION_ALIAS, 'any', 'incoming')
            nat = {'disabled': '0', 'nordr': '1', 'sequence': '1', 'interface': 'wan', 'ipprotocol': 'inet',
                   'protocol': '', 'source': {'network': REGION_ALIAS, 'port': '', 'not': '0'},
                   'destination': {'network': 'any', 'port': '', 'not': '0'},
                   'descr': REGION_DESCR + ' of port forwards'}
        if direction in ('outgoing', 'both'):
            rules['outgoing'] = rule('any', REGION_ALIAS, 'outgoing')
        return rules, nat

    def _region_block(self, region, changes):
        before = len(changes)
        if region:
            url = self.api.get('/api/firewall/alias/get').get('alias', {}).get('geoip', {}).get('url')
            if not url:
                logger.warning('Skipping region blocking: OPNsense has no GeoIP source. Set one in '
                               'Firewall > Aliases > GeoIP settings (e.g. a MaxMind GeoLite2 Country URL)')
                region = {}
        aliases = [row for row in self.api.get('/api/firewall/alias/search_item').get('rows', [])
                   if row.get('name') == REGION_ALIAS]
        filters = {row['description']: row for row in self.api.get('/api/firewall/filter/search_rule').get('rows', [])
                   if (row.get('description') or '').startswith(REGION_DESCR)}
        nats = [row for row in self.api.get('/api/firewall/d_nat/search_rule').get('rows', [])
                if (row.get('descr') or '').startswith(REGION_DESCR)]
        rules, nat = self._region_rules(region['direction']) if region else ({}, None)

        # the alias first, then what uses it
        if region:
            content = '\n'.join(region['countries'])
            alias = {'enabled': '1', 'name': REGION_ALIAS, 'type': 'geoip', 'proto': 'IPv4,IPv6',
                     'content': content, 'description': REGION_DESCR}
            current = aliases[0] if aliases else None
            if current is None:
                changes.append('Region blocking alias (%s): add' % ', '.join(region['countries']))
                self._post('/api/firewall/alias/add_item', {'alias': alias})
            elif (sorted(re.split(r'[\s,]+', (current.get('content') or '').strip().upper()))
                    != region['countries'] or current.get('enabled') != '1'):
                changes.append('Region blocking alias: now %s' % ', '.join(region['countries']))
                self._post('/api/firewall/alias/set_item/' + current['uuid'], {'alias': alias})
        for which, want in sorted(rules.items()):
            current = filters.pop(want['description'], None)
            if current is None:
                changes.append('Rule %r: add' % want['description'])
                self._post('/api/firewall/filter/add_rule', {'rule': want})
            elif any((current.get(key) or '') != want[key] for key in
                     ('action', 'interface', 'direction', 'source_net', 'destination_net', 'enabled', 'log')):
                changes.append('Rule %r: update' % want['description'])
                self._post('/api/firewall/filter/set_rule/' + current['uuid'], {'rule': want})
        if nat and not nats:
            changes.append('NAT rule %r: add' % nat['descr'])
            self._post('/api/firewall/d_nat/add_rule', {'rule': nat})
        elif nats:
            # keep one when it is still wanted
            for current in nats[1 if nat else 0:]:
                changes.append('NAT rule %r: remove' % current['descr'])
                self._post('/api/firewall/d_nat/del_rule/' + current['uuid'])
        for description, current in sorted(filters.items()):
            changes.append('Rule %r: remove' % description)
            self._post('/api/firewall/filter/del_rule/' + current['uuid'])
        if not region and aliases and _owned(aliases[0].get('description')):
            changes.append('Region blocking alias: remove')
            self._post('/api/firewall/alias/del_item/' + aliases[0]['uuid'])
        return len(changes) > before


def _interface_for(address, assigned):
    """The OPNsense interface whose static subnet holds an address."""
    for row in assigned:
        try:
            if ipaddress.ip_address(address) in ipaddress.ip_interface(row.get('ipaddr') or '').network:
                return row.get('identifier')
        except ValueError:
            continue
    return None
