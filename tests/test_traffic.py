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
