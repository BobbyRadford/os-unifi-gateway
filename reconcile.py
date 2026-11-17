"""Make OPNsense match what the controller wants for this gateway.

The controller sends its whole configuration for the gateway as `system_cfg`
(see provision.py). `intent_from_system_cfg` reads the parts this project
supports out of it, and `Reconciler` changes OPNsense through its REST API
until it matches:

- DHCP (Kea): each subnet's address pool and lease time, and its
  reservations ("Fixed IP" on a client in the UniFi UI), matched by MAC.
- Port forwards (Destination NAT), each with its own pass rule.

UniFi is the source of truth for everything listed above, but the reconciler
only ever deletes objects it created itself. It marks them by starting their
description with OWNER_TAG. Objects someone made by hand in OPNsense are
updated when UniFi asks for something different (a reservation for the same
MAC, say) but are never removed. Kea subnets that don't exist yet are skipped,
not created.

Set `[apply] mode` in the config file: `off` (default) does nothing, `plan`
only logs what it would change, and `apply` changes OPNsense.
"""
import ipaddress
import logging
from dataclasses import dataclass, field

logger = logging.getLogger('unifi-gateway')

OWNER_TAG = '[unifi]'
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


@dataclass
class PortForward:
    name: str
    protocol: str                       # OPNsense name: tcp, udp, tcp/udp
    external_port: str
    internal_ip: str
    internal_port: str
    source: str = ''                    # empty for any


@dataclass
class Intent:
    dhcp: list = field(default_factory=list)
    port_forwards: list = field(default_factory=list)


def intent_from_system_cfg(cfg):
    """Read the supported parts of a UDAPI system_cfg."""
    udapi = cfg.get('udapi', cfg)
    intent = Intent()

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
    return intent


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
        kea = self._kea(intent.dhcp, changes)
        nat = self._port_forwards(intent.port_forwards, changes)
        if self.mode == 'apply':
            if kea:
                self._post('/api/kea/service/reconfigure')
            if nat:
                self._post('/api/firewall/d_nat/apply')
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

    # Kea DHCPv4

    def _kea(self, scopes, changes):
        if not scopes:
            return False
        before = len(changes)
        subnets = {row['subnet']: row for row in
                   self.api.get('/api/kea/dhcpv4/search_subnet').get('rows', [])}
        reservations = self.api.get('/api/kea/dhcpv4/search_reservation').get('rows', [])
        # a subnet without its own lease time uses the global one
        general = self.api.get('/api/kea/dhcpv4/get').get('dhcpv4', {}).get('general', {})
        default_lease = str(general.get('valid_lifetime') or '')

        for scope in scopes:
            subnet = subnets.get(scope.subnet)
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
            summary = '%s %s -> %s:%s' % (forward.protocol, forward.external_port,
                                          forward.internal_ip, forward.internal_port)
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
