from collectors.traffic import StateCounter


def state(id, src, dst, sent, received, direction='in'):
    return {'id': id, 'direction': direction, 'src_addr': src, 'dst_addr': dst,
            'bytes': [sent, received]}


def test_counts_growth_from_the_first_update():
    counter = StateCounter()
    # a download already running when counting starts adds only what follows
    counter.update([state('a', '10.0.0.5', '1.1.1.1', 100, 5000)])
    assert counter.totals == {}
    counter.update([state('a', '10.0.0.5', '1.1.1.1', 150, 8000),
                    state('b', '10.0.0.5', '9.9.9.9', 10, 20)])
    assert counter.totals == {'10.0.0.5': {'tx_bytes': 60, 'rx_bytes': 3020}}


def test_a_closed_connection_stays_counted():
    counter = StateCounter()
    counter.update([])
    counter.update([state('a', '10.0.0.5', '1.1.1.1', 10, 900)])
    counter.update([])
    counter.update([state('b', '10.0.0.5', '1.1.1.1', 1, 2)])
    assert counter.totals['10.0.0.5'] == {'tx_bytes': 11, 'rx_bytes': 902}


def test_both_clients_of_a_local_connection_count_once():
    counter = StateCounter()
    counter.update([])
    counter.update([
        # a LAN client pulls a camera stream across VLANs: its inbound state on
        # the LAN and the outbound one on the camera's VLAN carry the same bytes
        state('in', '10.0.0.20', '10.0.50.100', 300, 70000),
        state('out', '10.0.0.20', '10.0.50.100', 300, 70000, direction='out'),
        # a port forward reaches a client from the internet
        state('fwd', '8.8.8.8', '10.0.0.30', 40, 4000),
    ])
    assert counter.totals == {
        '10.0.0.20': {'tx_bytes': 300, 'rx_bytes': 70000},
        '10.0.50.100': {'tx_bytes': 70000, 'rx_bytes': 300},
        '10.0.0.30': {'tx_bytes': 4000, 'rx_bytes': 40},
    }


def test_skips_ipv6_and_bad_rows():
    counter = StateCounter()
    counter.update([])
    counter.update([state('a', 'fd00::5', '2001:db8::1', 1, 2),
                    {'id': 'b', 'direction': 'in', 'src_addr': '10.0.0.5', 'bytes': None},
                    {'direction': 'in', 'src_addr': '10.0.0.5', 'bytes': [1, 2]}])
    assert counter.totals == {}


def test_countries_of_the_far_end():
    countries = {'8.8.8.8': 'US', '81.2.69.142': 'GB'}
    counter = StateCounter(country=countries.get)
    counter.update([])
    counter.update([
        state('a', '10.0.0.5', '8.8.8.8', 10, 100),
        state('b', '10.0.0.5', '81.2.69.142', 1, 2),
        # reached through a port forward
        state('c', '8.8.8.8', '10.0.0.30', 7, 70),
        # between two clients: no country
        state('d', '10.0.0.5', '10.0.40.2', 5, 5),
    ])
    assert counter.countries == {
        '10.0.0.5': {'US': [10, 100], 'GB': [1, 2]},
        '10.0.0.30': {'US': [70, 7]},
    }


def flow_state(id, src, sport, dst, dport, sent, received, proto='tcp'):
    row = state(id, src, dst, sent, received)
    row.update(proto=proto, src_port=str(sport), dst_port=str(dport), pkts=[sent // 10, received // 10])
    return row


def test_connections_are_states_that_are_new_or_carried_traffic():
    counter = StateCounter(country={'8.8.8.8': 'US'}.get)
    # the first read reports every open connection, counted from when it began
    counter.update([flow_state('a', '10.0.0.5', 50000, '8.8.8.8', 443, 100, 5000),
                    flow_state('b', '10.0.0.5', 40000, '10.0.0.1', 53, 60, 120, proto='udp'),
                    flow_state('c', '10.0.0.5', 1, '10.0.0.1', 1, 10, 10, proto='pfsync')])
    assert counter.take_connections() == [
        {'ip': {'saddr': '10.0.0.5', 'daddr': '8.8.8.8', 'protocol': 6, 'sport': 50000, 'dport': 443},
         'stats': {'txBytes': 100, 'rxBytes': 5000, 'txPackets': 10, 'rxPackets': 500},
         'region': {'dst': 'US'}},
        {'ip': {'saddr': '10.0.0.5', 'daddr': '10.0.0.1', 'protocol': 17, 'sport': 40000, 'dport': 53},
         'stats': {'txBytes': 60, 'rxBytes': 120, 'txPackets': 6, 'rxPackets': 12}},
    ]
    assert counter.take_connections() == []
    # only the download moved
    counter.update([flow_state('a', '10.0.0.5', 50000, '8.8.8.8', 443, 150, 9000),
                    flow_state('b', '10.0.0.5', 40000, '10.0.0.1', 53, 60, 120, proto='udp')])
    assert [c['stats']['rxBytes'] for c in counter.take_connections()] == [9000]
