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
"""
import ipaddress

TRAFFIC_INTERVAL = 10


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


class StateCounter:
    """Totals per address, {address: {'tx_bytes', 'rx_bytes'}} as a client
    sees them: tx is what it sent. They start at zero when counting starts,
    so connections already open then add only their bytes from that point.

    With `country`, a function giving the ISO code of a public address,
    `countries` also holds each client's bytes per country of the far end:
    {address: {iso: [tx, rx]}}."""

    def __init__(self, country=None):
        self.totals = {}
        self.countries = {}
        self._country = country
        self._last = None

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
            if first:
                continue
            before = last.get(row['id'], (0, 0))
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
