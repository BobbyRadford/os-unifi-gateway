# -*- coding: utf-8 -*-
"""Per-client byte counts from the router's firewall state table.

pf keeps a state for each connection with the bytes it has carried in each
direction, and keeps it for a while after the connection's last packet: at
least 30 s for UDP and 45-90 s for a closed TCP connection (ICMP errors, at
10 s, are the shortest). Reading the table every TRAFFIC_INTERVAL seconds
therefore sees every connection, short ones included, and every byte of it.

Each poll adds how much each state's counts grew since the last poll, so a
state's bytes stay counted after it is gone. Only inbound states are read,
since a routed connection also has an outbound state on the interface it
leaves by with the same counts.

Each poll also reports the states that are new or carried traffic as the
inform's `connections`, which the controller keeps as Traffic Flows (the
Flows tab, and the clients and destinations Insights ranks by flow count).
`blocked_triggers` does the same for the packets the firewall blocked.
"""
import ipaddress
import re

TRAFFIC_INTERVAL = 10
PROTOCOLS = {'icmp': 1, 'tcp': 6, 'udp': 17, 'ipv6-icmp': 58}
# Hostnames kept for destinations (StateCounter.hostnames) before starting over
MAX_HOSTNAMES = 20000


def _public_address(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_global


def _client_address(address):
    """True for an IPv4 address that may be a client: the host table lists
    clients by IPv4 address, and remote addresses need no totals."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    return ip.version == 4 and ip.is_private


def _ports(ip, sport, dport):
    """Add the ports, given as text, to a connection's `ip`."""
    for key, port in (('sport', sport), ('dport', dport)):
        if str(port or '').isdigit():
            ip[key] = int(port)
    return ip


def _regions(country, src, dst):
    """{'src', 'dst'}: the country of each public end, for the controller's
    ranking of destinations and regions."""
    if not country:
        return {}
    regions = {end: country(address) for end, address in (('src', src), ('dst', dst))
               if _public_address(address)}
    return {end: iso for end, iso in regions.items() if iso}


def blocked_triggers(rows, country=None):
    """The inform's `triggers` for the packets the firewall blocked, from
    `rows` of Source.firewall_log. A trigger names the firewall policy that
    acted. The controller keeps one as a BLOCKED Traffic Flow when that
    policy blocks, or, as here, when it doesn't know the policy. Its id has
    to look like a MongoDB ObjectId, so it is the start of the OPNsense
    rule's hash."""
    triggers = []
    for row in rows:
        if row.get('action') != 'block' or not str(row.get('protonum') or '').isdigit():
            continue
        src, dst = row.get('src'), row.get('dst')
        rule = str(row.get('rid') or '')
        trigger = {
            'id': rule[:24] if re.fullmatch(r'[0-9a-f]{24,}', rule) else '0' * 24,
            'type': 'FIREWALL_POLICY',
            'ip': _ports({'saddr': src, 'daddr': dst, 'protocol': int(row['protonum'])},
                         row.get('srcport'), row.get('dstport')),
            'stats': {'bytes': int(row['length']) if str(row.get('length') or '').isdigit() else 0,
                      'packets': 1},
        }
        if row.get('__timestamp__'):
            trigger['timestamp'] = row['__timestamp__']
        region = _regions(country, src, dst)
        if region:
            trigger['region'] = region
        triggers.append(trigger)
    return triggers


class StateCounter:
    """Totals per address, {address: {'tx_bytes', 'rx_bytes'}} as a client
    sees them: tx is what it sent. They start at zero when counting starts,
    so connections already open then add only their bytes from that point.

    With `country`, a function giving the ISO code of a public address,
    `countries` also holds each client's bytes per country of the far end:
    {address: {iso: [tx, rx]}}.

    `hostnames` ({address: name}, filled by the caller) names the public
    destinations of the connections reported."""

    def __init__(self, country=None):
        self.totals = {}
        self.countries = {}
        self.hostnames = {}
        self._country = country
        self._last = None
        self._connections = []

    def take_connections(self):
        """The inform's `connections` since the last call: one conntrack
        event per state that is new or carried traffic, with the state's
        counts so far. The controller merges a connection's events into one
        flow and takes the latest counts."""
        connections, self._connections = self._connections, []
        return connections

    def update(self, rows):
        """Add the growth of each state in `rows` (Source.states) since the
        last update. The first update only records where each state is."""
        first = self._last is None
        last = self._last or {}
        now = {}
        for row in rows:
            if row.get('direction') != 'in' or not row.get('id'):
                continue
            try:
                # bytes sent by the source, then bytes sent to it
                sent, received = (int(n) for n in row.get('bytes') or ())
            except (TypeError, ValueError):
                continue
            now[row['id']] = (sent, received)
            before = last.get(row['id'])
            if before != (sent, received):
                self._add_connection(row, sent, received)
            if first:
                continue
            before = before or (0, 0)
            sent, received = max(sent - before[0], 0), max(received - before[1], 0)
            # a connection between two clients counts for both of them
            src, dst = row.get('src_addr'), row.get('dst_addr')
            self._add(src, sent, received)
            self._add(dst, received, sent)
            if self._country and (sent or received):
                # a client reaching out, or reached through a port forward
                if _client_address(src) and _public_address(dst):
                    self._add_country(src, dst, sent, received)
                elif _client_address(dst) and _public_address(src):
                    self._add_country(dst, src, received, sent)
        self._last = now

    def _add_connection(self, row, sent, received):
        protocol = PROTOCOLS.get(row.get('proto'))
        if protocol is None:
            return
        src, dst = row.get('src_addr'), row.get('dst_addr')
        ip = _ports({'saddr': src, 'daddr': dst, 'protocol': protocol},
                    row.get('src_port'), row.get('dst_port'))
        try:
            sent_packets, received_packets = (int(n) for n in row.get('pkts') or ())
        except (TypeError, ValueError):
            sent_packets = received_packets = 0
        connection = {'ip': ip, 'stats': {
            'txBytes': sent, 'rxBytes': received,
            'txPackets': sent_packets, 'rxPackets': received_packets}}
        region = _regions(self._country, src, dst)
        if region:
            connection['region'] = region
        if _public_address(dst) and self.hostnames.get(dst):
            connection['hostnames'] = [self.hostnames[dst]]
        self._connections.append(connection)

    def _add_country(self, client, remote, tx, rx):
        iso = self._country(remote)
        if iso:
            entry = self.countries.setdefault(client, {}).setdefault(iso, [0, 0])
            entry[0] += tx
            entry[1] += rx

    def _add(self, address, tx, rx):
        if not (tx or rx) or not _client_address(address):
            return
        entry = self.totals.setdefault(address, {'tx_bytes': 0, 'rx_bytes': 0})
        entry['tx_bytes'] += tx
        entry['rx_bytes'] += rx
