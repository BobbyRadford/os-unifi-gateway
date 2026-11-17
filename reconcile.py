"""Make OPNsense match what the controller wants for this gateway.

The controller sends its whole configuration for the gateway as `system_cfg`
(see provision.py). `intent_from_system_cfg` reads the parts this project
supports out of it, and `Reconciler` changes OPNsense through its REST API
until it matches:

- Networks with a VLAN ID and a gateway address: a VLAN on the LAN port, an
  interface with the gateway address, a Kea subnet that Kea listens on, and
  a rule passing the network's traffic. An isolated network's rule leaves
  out the other local networks, as UniFi's isolation does: it can't start
  connections to them, but they can still reach it. NetFlow captures each
  network's interface too, if it is capturing the LAN.
- DHCP (Kea): each subnet's address pool and lease time (and, for the
  networks above, its router and DNS server), and its reservations ("Fixed IP" on a client in the UniFi UI), matched by MAC.
- Port forwards (Destination NAT), each with its own pass rule.
- DNS records from the UI's DNS page (A and AAAA), as Unbound host overrides.

UniFi is the source of truth for everything listed above, but the reconciler
only ever deletes objects it created itself. It marks them by starting their
description with OWNER_TAG. Objects someone made by hand in OPNsense are
updated when UniFi asks for something different (a reservation for the same
MAC, say) but are never removed. A Kea subnet is only created for a network
the reconciler made, so the LAN's subnet has to exist already.

Set `[apply] mode` in the config file: `off` (default) does nothing, `plan`
only logs what it would change, and `apply` changes OPNsense.
"""
import ipaddress
import logging
import re
from dataclasses import dataclass, field

logger = logging.getLogger('unifi-gateway')

OWNER_TAG = '[unifi]'

# The UXG port the LAN runs on. Its VLANs become VLANs on OPNsense's LAN NIC.
LAN_PORT = 'eth1'
MODES = ('off', 'plan', 'apply')

# UniFi port forward protocols, as OPNsense names them
PROTOCOLS = {'tcp': 'tcp', 'udp': 'udp', 'tcp_udp': 'tcp/udp', 'tcp/udp': 'tcp/udp'}


# ── What the controller wants ────────────────────────────────────────────

@dataclass
class DhcpScope:
    subnet: str                         # "10.0.0.0/24"
    range_start: str
    range_stop: str
    lease_time: int
    reservations: dict = field(default_factory=dict)   # {mac: ip}
    dns_servers: list = field(default_factory=list)


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
class Intent:
    networks: list = field(default_factory=list)
    dhcp: list = field(default_factory=list)
    port_forwards: list = field(default_factory=list)
    dns_records: dict = field(default_factory=dict)    # {(fqdn, 'A'|'AAAA'): address}


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
        intent.dhcp.append(DhcpScope(
            subnet=str(subnet),
            range_start=server['rangeStart'],
            range_stop=server['rangeStop'],
            lease_time=int(server.get('leaseTime', 86400)),
            reservations=reservations,
            dns_servers=list(server.get('dnsServers') or []),
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
    return intent


def _networks_from(udapi):
    """A UXG carries each VLAN network on a bridge (br40) over a VLAN
    interface on the LAN port (eth1.40). VLAN-only networks have no address
    and are left alone, since the gateway doesn't route them."""
    interfaces = udapi.get('interfaces', [])
    tags = {}
    for iface in interfaces:
        vlan = iface.get('vlan') or {}
        if (iface.get('identification', {}).get('type') == 'vlan'
                and (vlan.get('interface') or {}).get('id') == LAN_PORT):
            tags[iface['identification']['id']] = vlan['id']

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
        if ident.get('type') != 'bridge':
            continue
        members = [tags[m['id']] for m in (iface.get('bridge') or {}).get('interfaces', [])
                   if m.get('id') in tags]
        address = next((a['cidr'] for a in iface.get('addresses') or []
                        if a.get('version') == 'v4' and a.get('type') == 'static' and a.get('cidr')),
                       None)
        if len(members) != 1 or not address:
            continue
        network = Network(vlan=int(members[0]), address=address,
                          name=names.get(ident['id']) or 'VLAN%s' % members[0])
        network.isolated = network.subnet in sets.get('isolated_subnets', [])
        network.others = sorted(n for n in sets.get('local_network', []) if n != network.subnet)
        networks.append(network)
    return sorted(networks, key=lambda n: n.vlan)


# ── Making OPNsense match ────────────────────────────────────────────────

def _owned(description):
    return (description or '').startswith(OWNER_TAG)


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
        changes = []
        # new networks first and old ones last, so nothing is removed while
        # a Kea subnet or rule still refers to it
        ifaces, removals = self._networks(intent.networks, changes)
        kea = self._kea(intent.dhcp, intent.networks, ifaces, removals, changes)
        rules = self._rules(intent.networks, ifaces, changes)
        netflow = self._netflow(ifaces, removals, changes)
        nat = self._port_forwards(intent.port_forwards, changes)
        dns = self._dns_records(intent.dns_records, changes)
        if self.mode == 'apply':
            if kea:
                self._post('/api/kea/service/reconfigure')
            if rules:
                self._post('/api/firewall/filter/apply')
            if netflow:
                self._post('/api/diagnostics/netflow/reconfigure')
            if nat:
                self._post('/api/firewall/d_nat/apply')
            if dns:
                self._post('/api/unbound/service/reconfigure')
        self._remove_networks(removals, changes)
        for text in changes:
            logger.info('%s: %s', 'Applied' if self.mode == 'apply' else 'Would apply', text)
        if not changes:
            logger.debug('OPNsense already matches the controller')
        return changes

    def _post(self, path, body=None):
        if self.mode != 'apply':
            return {}
        response = self.api.post(path, body or {})
        if isinstance(response, dict) and response.get('result') == 'failed':
            raise RuntimeError('%s failed: %s' % (path, response.get('validations')))
        return response

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
    def _rule(network, iface):
        return {
            'enabled': '1', 'action': 'pass', 'quick': '1', 'direction': 'in',
            'interface': iface, 'ipprotocol': 'inet', 'source_net': iface,
            'destination_net': ','.join(network.others) if network.isolated and network.others else 'any',
            'destination_not': '1' if network.isolated and network.others else '0',
            'description': '%s VLAN %d: %s%s' % (OWNER_TAG, network.vlan, network.name,
                                                ' (isolated)' if network.isolated else ''),
        }

    def _rules(self, networks, ifaces, changes):
        before = len(changes)
        owned = {}
        for row in self.api.get('/api/firewall/filter/search_rule').get('rows', []):
            match = re.match(re.escape(OWNER_TAG) + r' VLAN (\d+):', row.get('description') or '')
            if match:
                owned[int(match.group(1))] = row
        for network in networks:
            want = self._rule(network, ifaces.get(network.vlan) or '')
            current = owned.get(network.vlan)
            if current is None:
                changes.append('Rule %r: add' % want['description'])
                self._post('/api/firewall/filter/add_rule', {'rule': want})
            elif any(current.get(key) != want[key] for key in
                     ('description', 'source_net', 'destination_net', 'destination_not')):
                changes.append('Rule %r: update' % want['description'])
                self._post('/api/firewall/filter/set_rule/' + current['uuid'], {'rule': want})
        wanted = {network.vlan for network in networks}
        for vlan, current in sorted(owned.items()):
            if vlan not in wanted:
                changes.append('Rule %r: remove' % current['description'])
                self._post('/api/firewall/filter/del_rule/' + current['uuid'])
        return len(changes) > before

    # NetFlow, for per-client traffic

    def _netflow(self, ifaces, removals, changes):
        """Captures traffic on each network's interface too, but only when
        NetFlow is already capturing something."""
        if not ifaces and not removals:
            return False
        config = self.api.get('/api/diagnostics/netflow/getconfig').get('netflow', {})
        capture = config.get('capture', {}).get('interfaces') or {}
        current = [key for key, value in capture.items() if value.get('selected')]
        if not current:
            return False
        drop = {iface['identifier'] for _, iface in removals if iface}
        want = [i for i in current if i not in drop]
        want += [i for i in ifaces.values() if i and i not in want]
        if want == current:
            return False
        changes.append('NetFlow capture: %s -> %s' % (','.join(current), ','.join(want)))
        self._post('/api/diagnostics/netflow/setconfig', {'netflow': {'capture': {'interfaces': ','.join(want)}}})
        return True

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
        listening = general.get('interfaces') or {}
        if isinstance(listening, dict):
            listening = [key for key, value in listening.items() if value.get('selected')]
        elif isinstance(listening, str):
            listening = [i for i in listening.split(',') if i]
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
            # Kea's autocollect doesn't fill in a subnet made through the
            # API, so the reconciler sets the options of its own subnets
            options = {}
            if scope.subnet in managed:
                gateway = str(ipaddress.ip_interface(managed[scope.subnet].address).ip)
                options = {'routers': gateway,
                           'domain_name_servers': ','.join(scope.dns_servers) or gateway}
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
                          'pools': '%s - %s' % (scope.range_start, scope.range_stop),
                          'option_data.routers': options['routers'],
                          'option_data.domain_name_servers': options['domain_name_servers']}
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
            if any(subnet.get('option_data.' + key) != value for key, value in options.items()):
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
        owned = {row['descr'][len(OWNER_TAG):].strip(): row
                 for row in rows if _owned(row.get('descr'))}
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
