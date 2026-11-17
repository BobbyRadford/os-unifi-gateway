import copy

import pytest

from reconcile import OWNER_TAG, Intent, DhcpScope, Network, PortForward, Reconciler, intent_from_system_cfg

SUBNET_UUID = 'sub-1'

# Shapes captured from a Network 10.6.109 controller
SYSTEM_CFG = {'udapi': {
    'services': {'dhcpServers': [{
        'enabled': True, 'ipVersion': 'v4', 'gatewayAddress': '10.0.0.1', 'ipv4Netmask': 24,
        'leaseTime': 4000, 'rangeStart': '10.0.0.100', 'rangeStop': '10.0.0.254',
        'interfaces': [{'id': 'br0'}],
        'staticLeases': [{'addresses': ['10.0.0.112'], 'id': '00:00:5E:00:53:70'}],
    }]},
    'firewall/nat': [
        {'chain': 'POSTROUTING', 'enabled': True, 'id': 1, 'target': 'MASQUERADE',
         'outInterface': {'id': 'eth0'}, 'source': {'sets': ['!ADDRv4_eth0']}},
        {'chain': 'PREROUTING', 'description': 'PortForward DNAT [plex]',
         'destination': {'port': '32400', 'sets': ['ADDRv4_eth0']}, 'enabled': True, 'id': 2,
         'protocol': 'tcp', 'source': {}, 'target': 'DNAT',
         'translation': {'address': '10.0.0.50', 'port': '32400'}},
        {'chain': 'POSTROUTING', 'description': 'PortForward MASQUERADE [plex]',
         'destination': {'address': '10.0.0.50', 'port': '32400'}, 'enabled': True, 'id': 3,
         'protocol': 'tcp', 'source': {'sets': ['NETv4_br0']}, 'target': 'MASQUERADE'},
    ],
}}
SYSTEM_CFG['udapi']['services']['dnsForwarder'] = {'hostRecords': [
    # the controller's own records: no ttl
    {'address': {'address': '10.0.0.5', 'version': 'v4'}, 'hostName': 'unifi.internal',
     'registerNonQualified': True},
    {'address': {'address': '10.0.0.1', 'version': 'v4'}, 'hostName': 'setup.ui.com',
     'registerNonQualified': False},
    # one from the UI's DNS page
    {'address': {'address': '10.0.0.50', 'origin': None, 'version': 'v4'},
     'hostName': 'plex.internal', 'ttl': 0, 'registerNonQualified': False},
]}


class FakeOPNsense:
    """Answers the GETs the reconciler makes and records its POSTs."""

    def __init__(self):
        self.subnets = [{'uuid': SUBNET_UUID, 'subnet': '10.0.0.0/24',
                         'pools': '10.0.0.100 - 10.0.0.254', 'valid_lifetime': ''}]
        self.reservations = []
        self.nat = []
        self.hosts = []
        self.lease = '4000'
        self.kea_interfaces = ['lan']
        self.assigned = [{'uuid': 'lan', 'identifier': 'lan', 'if': 'vtnet1',
                          'ipaddr': '10.0.0.1/24', 'enable': '1'}]
        self.vlans = []
        self.rules = []
        self.netflow = ['lan']
        self.posts = []

    def get(self, path):
        general = {'valid_lifetime': self.lease,
                   'interfaces': {i: {'value': i.upper(), 'selected': 1} for i in self.kea_interfaces}}
        return {
            '/api/interfaces/assignment/search_item': {'rows': self.assigned},
            '/api/interfaces/vlan_settings/search_item': {'rows': self.vlans},
            '/api/firewall/filter/search_rule': {'rows': self.rules},
            '/api/diagnostics/netflow/getconfig': {'netflow': {'capture': {'interfaces': {
                i: {'value': i.upper(), 'selected': 1} for i in self.netflow}}}},
            '/api/kea/dhcpv4/search_subnet': {'rows': self.subnets},
            '/api/kea/dhcpv4/search_reservation': {'rows': self.reservations},
            '/api/kea/dhcpv4/get': {'dhcpv4': {'general': general}},
            '/api/firewall/d_nat/search_rule': {'rows': self.nat},
            '/api/unbound/settings/search_host_override': {'rows': self.hosts},
        }[path]

    def post(self, path, body=None):
        self.posts.append((path, copy.deepcopy(body)))
        # OPNsense names new VLAN devices and interfaces itself
        if path == '/api/interfaces/vlan_settings/add_item':
            vlan = dict(body['vlan'], uuid='v' + body['vlan']['tag'], vlanif='vlan0.' + body['vlan']['tag'])
            self.vlans.append(vlan)
        elif path == '/api/interfaces/assignment/add_item':
            name = 'opt%d' % len(self.assigned)
            self.assigned.append(dict(body['interface'], uuid=name, identifier=name))
            for vlan in self.vlans:
                if vlan['vlanif'] == body['interface']['if']:
                    vlan['vlanif'] += ' [%s]' % body['interface']['descr']
        elif path == '/api/kea/dhcpv4/add_subnet':
            return {'result': 'saved', 'uuid': 'sub-new'}
        return {'result': 'saved'}

    def paths(self):
        return [path for path, _ in self.posts]


def reservation(mac, ip, description='', uuid=None):
    return {'uuid': uuid or 'r-' + ip, 'subnet': SUBNET_UUID, 'hw_address': mac,
            'ip_address': ip, 'description': description}


def test_intent_from_captured_system_cfg():
    intent = intent_from_system_cfg(SYSTEM_CFG)
    assert intent.dhcp == [DhcpScope('10.0.0.0/24', '10.0.0.100', '10.0.0.254', 4000,
                                     {'00:00:5e:00:53:70': '10.0.0.112'})]
    # only the DNAT half of a port forward matters; its masquerade is UniFi's
    assert intent.port_forwards == [PortForward('plex', 'tcp', '32400', '10.0.0.50', '32400')]
    assert intent.dns_records == {('plex.internal', 'A'): '10.0.0.50'}


def test_plan_mode_never_posts():
    api = FakeOPNsense()
    changes = Reconciler(api, 'plan').run(intent_from_system_cfg(SYSTEM_CFG))
    assert len(changes) == 3
    assert api.posts == []


def test_off_mode_does_nothing():
    api = FakeOPNsense()
    assert Reconciler(api, 'off').run(intent_from_system_cfg(SYSTEM_CFG)) == []


def test_unknown_mode_is_rejected():
    with pytest.raises(ValueError):
        Reconciler(FakeOPNsense(), 'yolo')


def test_apply_adds_reservation_and_forward_then_reloads():
    api = FakeOPNsense()
    Reconciler(api, 'apply').run(intent_from_system_cfg(SYSTEM_CFG))
    assert api.paths() == [
        '/api/kea/dhcpv4/add_reservation',
        '/api/firewall/d_nat/add_rule',
        '/api/unbound/settings/add_host_override',
        '/api/kea/service/reconfigure',
        '/api/firewall/d_nat/apply',
        '/api/unbound/service/reconfigure',
    ]
    host = api.posts[2][1]['host']
    assert (host['hostname'], host['domain'], host['rr'], host['server']) == ('plex', 'internal', 'A', '10.0.0.50')
    added = api.posts[0][1]['reservation']
    assert added['hw_address'] == '00:00:5e:00:53:70'
    assert added['description'].startswith(OWNER_TAG)
    rule = api.posts[1][1]['rule']
    assert rule['destination'] == {'network': 'wanip', 'port': '32400', 'not': '0'}
    assert (rule['target'], rule['local-port'], rule['pass']) == ('10.0.0.50', '32400', 'pass')


def test_matching_state_changes_nothing():
    api = FakeOPNsense()
    api.reservations = [reservation('00:00:5e:00:53:70', '10.0.0.112', OWNER_TAG)]
    api.nat = [{'uuid': 'n1', 'descr': OWNER_TAG + ' plex', 'protocol': 'tcp',
                'destination.port': '32400', 'target': '10.0.0.50', 'local-port': '32400',
                'source.network': 'any', 'disabled': '0'}]
    api.hosts = [{'uuid': 'h1', 'hostname': 'plex', 'domain': 'internal', 'rr': 'A',
                  'server': '10.0.0.50', 'enabled': '1', 'description': OWNER_TAG}]
    assert Reconciler(api, 'apply').run(intent_from_system_cfg(SYSTEM_CFG)) == []
    assert api.posts == []


def test_subnet_inherits_global_lease_time():
    api = FakeOPNsense()
    api.lease = '86400'
    Reconciler(api, 'apply').run(Intent(dhcp=[DhcpScope('10.0.0.0/24', '10.0.0.100', '10.0.0.200', 4000)]))
    assert api.posts[0] == ('/api/kea/dhcpv4/set_subnet/' + SUBNET_UUID,
                            {'subnet4': {'pools': '10.0.0.100 - 10.0.0.200', 'valid_lifetime': '4000'}})


def test_only_owned_reservations_are_removed():
    api = FakeOPNsense()
    api.reservations = [
        reservation('74:ac:b9:17:3d:65', '10.0.0.10', 'USW 16 PoE'),       # made by hand
        reservation('aa:aa:aa:aa:aa:01', '10.0.0.20', OWNER_TAG + ' x'),   # ours, gone from UniFi
    ]
    Reconciler(api, 'apply').run(Intent(dhcp=[DhcpScope('10.0.0.0/24', '10.0.0.100', '10.0.0.254', 4000)]))
    assert api.paths() == ['/api/kea/dhcpv4/del_reservation/r-10.0.0.20', '/api/kea/service/reconfigure']


def test_hand_made_reservation_is_moved_when_unifi_asks():
    api = FakeOPNsense()
    api.reservations = [reservation('74:ac:b9:17:3d:65', '10.0.0.10', 'USW 16 PoE')]
    scope = DhcpScope('10.0.0.0/24', '10.0.0.100', '10.0.0.254', 4000, {'74:ac:b9:17:3d:65': '10.0.0.11'})
    Reconciler(api, 'apply').run(Intent(dhcp=[scope]))
    assert api.posts[0] == ('/api/kea/dhcpv4/set_reservation/r-10.0.0.10',
                            {'reservation': {'ip_address': '10.0.0.11'}})


def test_reservation_outside_subnet_is_skipped():
    api = FakeOPNsense()
    scope = DhcpScope('10.0.0.0/24', '10.0.0.100', '10.0.0.254', 4000, {'aa:aa:aa:aa:aa:02': '192.168.9.9'})
    assert Reconciler(api, 'apply').run(Intent(dhcp=[scope])) == []


def test_missing_kea_subnet_is_skipped():
    api = FakeOPNsense()
    scope = DhcpScope('10.0.40.0/24', '10.0.40.100', '10.0.40.254', 4000, {'aa:aa:aa:aa:aa:03': '10.0.40.5'})
    assert Reconciler(api, 'apply').run(Intent(dhcp=[scope])) == []
    assert api.posts == []


def test_owned_forward_is_updated_and_removed():
    api = FakeOPNsense()
    api.nat = [
        {'uuid': 'n1', 'descr': OWNER_TAG + ' plex', 'protocol': 'tcp', 'destination.port': '32400',
         'target': '10.0.0.49', 'local-port': '32400', 'source.network': 'any', 'disabled': '0'},
        {'uuid': 'n2', 'descr': OWNER_TAG + ' old', 'protocol': 'udp', 'destination.port': '1',
         'target': '10.0.0.2', 'local-port': '1', 'source.network': 'any', 'disabled': '0'},
        {'uuid': 'n3', 'descr': 'hand made', 'protocol': 'udp', 'destination.port': '2',
         'target': '10.0.0.3', 'local-port': '2', 'source.network': 'any', 'disabled': '0'},
    ]
    Reconciler(api, 'apply').run(Intent(port_forwards=[PortForward('plex', 'tcp', '32400', '10.0.0.50', '32400')]))
    assert api.paths() == ['/api/firewall/d_nat/set_rule/n1', '/api/firewall/d_nat/del_rule/n2',
                           '/api/firewall/d_nat/apply']


def test_failed_save_raises():
    api = FakeOPNsense()
    api.post = lambda path, body=None: {'result': 'failed', 'validations': {'x': 'bad'}}
    with pytest.raises(RuntimeError):
        Reconciler(api, 'apply').run(intent_from_system_cfg(SYSTEM_CFG))


def test_dns_records_only_remove_owned():
    api = FakeOPNsense()
    api.hosts = [
        {'uuid': 'h1', 'hostname': 'nas', 'domain': 'internal', 'rr': 'A', 'server': '10.0.0.9',
         'enabled': '1', 'description': 'hand made'},
        {'uuid': 'h2', 'hostname': 'old', 'domain': 'internal', 'rr': 'A', 'server': '10.0.0.8',
         'enabled': '1', 'description': OWNER_TAG + ' x'},
    ]
    Reconciler(api, 'apply').run(Intent(dns_records={('nas.internal', 'A'): '10.0.0.7'}))
    assert api.posts == [
        ('/api/unbound/settings/set_host_override/h1', {'host': {'server': '10.0.0.7', 'enabled': '1'}}),
        ('/api/unbound/settings/del_host_override/h2', {}),
        ('/api/unbound/service/reconfigure', {}),
    ]


# A routed VLAN network as Network 10.6.109 sends it (TEST99, then isolated)
VLAN_CFG = {'udapi': {
    'interfaces': [
        {'identification': {'id': 'br0', 'type': 'bridge'}, 'bridge': {'id': 0, 'interfaces': [{'id': 'eth1'}]},
         'addresses': [{'cidr': '10.0.0.1/24', 'type': 'static', 'version': 'v4'}]},
        {'identification': {'id': 'eth1.40', 'type': 'vlan'}, 'vlan': {'id': 40, 'interface': {'id': 'eth1'}}},
        {'identification': {'id': 'br40', 'type': 'bridge'}, 'bridge': {'id': 40, 'interfaces': [{'id': 'eth1.40'}]},
         'addresses': []},
        {'identification': {'id': 'eth1.99', 'type': 'vlan'}, 'vlan': {'id': 99, 'interface': {'id': 'eth1'}}},
        {'identification': {'id': 'br99', 'type': 'bridge'}, 'bridge': {'id': 99, 'interfaces': [{'id': 'eth1.99'}]},
         'addresses': [{'cidr': '10.0.99.1/24', 'type': 'static', 'version': 'v4'}],
         'status': {'comment': 'LAN', 'enabled': True}},
    ],
    'services': {'dhcpServers': [{
        'enabled': True, 'ipVersion': 'v4', 'gatewayAddress': '10.0.99.1', 'ipv4Netmask': 24,
        'dnsServers': ['10.0.99.1'],
        'leaseTime': 86400, 'name': 'net_TEST99_br99_10-0-99-0-24', 'rangeStart': '10.0.99.100',
        'rangeStop': '10.0.99.200', 'interfaces': [{'id': 'br99'}]}]},
    'firewall/sets': [
        {'identification': {'name': 'local_network', 'type': 'address'}, 'entries': ['10.0.99.0/24', '10.0.0.0/24']},
        {'identification': {'name': 'isolated_subnets', 'type': 'address'}, 'entries': ['10.0.99.0/24']},
    ],
}}


def test_vlan_network_from_captured_system_cfg():
    # br0 is the untagged LAN and br40 a VLAN-only network: neither is created
    assert intent_from_system_cfg(VLAN_CFG).networks == [
        Network(99, 'TEST99', '10.0.99.1/24', isolated=True, others=['10.0.0.0/24'])]


def test_new_network_is_built_in_order():
    api = FakeOPNsense()
    Reconciler(api, 'apply').run(intent_from_system_cfg(VLAN_CFG))
    assert api.paths() == [
        '/api/interfaces/vlan_settings/add_item',
        '/api/interfaces/vlan_settings/reconfigure',
        '/api/interfaces/assignment/add_item',
        '/api/interfaces/assignment/reconfigure',
        '/api/kea/dhcpv4/set',
        '/api/kea/dhcpv4/add_subnet',
        '/api/firewall/filter/add_rule',
        '/api/firewall/filter/add_rule',
        '/api/diagnostics/netflow/setconfig',
        '/api/kea/service/reconfigure',
        '/api/firewall/filter/apply',
        '/api/diagnostics/netflow/reconfigure',
    ]
    posts = dict(api.posts)
    assert posts['/api/interfaces/vlan_settings/add_item']['vlan']['if'] == 'vtnet1'
    assert posts['/api/interfaces/assignment/add_item']['interface'] == {
        'if': 'vlan0.99', 'descr': 'TEST99', 'enable': '1', 'type4': 'staticv4', 'ipaddr': '10.0.99.1/24'}
    assert posts['/api/kea/dhcpv4/set'] == {'dhcpv4': {'general': {'interfaces': 'lan,opt1'}}}
    assert posts['/api/diagnostics/netflow/setconfig'] == {'netflow': {'capture': {'interfaces': 'lan,opt1'}}}
    subnet = posts['/api/kea/dhcpv4/add_subnet']['subnet4']
    assert subnet['pools'] == '10.0.99.100 - 10.0.99.200'
    assert subnet['option_data'] == {'routers': '10.0.99.1', 'domain_name_servers': '10.0.99.1'}
    block, allow = [body['rule'] for path, body in api.posts if path == '/api/firewall/filter/add_rule']
    # isolated: the other local networks are blocked ahead of the pass rule
    assert (block['action'], block['source_net'], block['destination_net']) == ('block', 'opt1', '10.0.0.0/24')
    assert (allow['action'], allow['interface'], allow['destination_net']) == ('pass', 'opt1', 'any')
    assert int(block['sequence']) < int(allow['sequence'])


def test_built_network_changes_nothing():
    api = FakeOPNsense()
    Reconciler(api, 'apply').run(intent_from_system_cfg(VLAN_CFG))
    api.subnets.append({'uuid': 'sub-new', 'subnet': '10.0.99.0/24', 'pools': '10.0.99.100 - 10.0.99.200',
                        'valid_lifetime': '86400', 'description': OWNER_TAG + ' TEST99',
                        'option_data.routers': '10.0.99.1', 'option_data.domain_name_servers': '10.0.99.1'})
    api.kea_interfaces = ['lan', 'opt1']
    api.netflow = ['lan', 'opt1']
    api.rules = [dict(body['rule'], uuid='f%d' % i) for i, (path, body) in enumerate(api.posts)
                 if path == '/api/firewall/filter/add_rule']
    api.posts = []
    assert Reconciler(api, 'apply').run(intent_from_system_cfg(VLAN_CFG)) == []


def test_plan_mode_plans_a_new_network_without_posting():
    api = FakeOPNsense()
    changes = Reconciler(api, 'plan').run(intent_from_system_cfg(VLAN_CFG))
    assert len(changes) == 5      # VLAN, interface, Kea subnet, and two rules
    assert api.posts == []


def test_turning_isolation_off_updates_the_rule():
    api = FakeOPNsense()
    Reconciler(api, 'apply').run(intent_from_system_cfg(VLAN_CFG))
    api.rules = [dict(body['rule'], uuid='f%d' % i) for i, (path, body) in enumerate(api.posts)
                 if path == '/api/firewall/filter/add_rule']
    block = next(r for r in api.rules if r['action'] == 'block')
    api.posts = []
    network = Network(99, 'TEST99', '10.0.99.1/24', others=['10.0.0.0/24'])
    Reconciler(api, 'apply').run(Intent(networks=[network]))
    rule_calls = [path for path in api.paths() if '/firewall/filter/' in path]
    assert rule_calls == ['/api/firewall/filter/del_rule/' + block['uuid'], '/api/firewall/filter/apply']


def test_removed_network_is_taken_apart_after_its_users():
    api = FakeOPNsense()
    api.vlans = [{'uuid': 'v99', 'if': 'vtnet1', 'tag': '99', 'vlanif': 'vlan0.99 [TEST99]', 'descr': OWNER_TAG + ' TEST99'},
                 {'uuid': 'v7', 'if': 'vtnet1', 'tag': '7', 'vlanif': 'vlan0.7', 'descr': 'hand made'}]
    api.assigned.append({'uuid': 'opt1', 'identifier': 'opt1', 'if': 'vlan0.99', 'ipaddr': '10.0.99.1/24', 'enable': '1'})
    api.kea_interfaces = ['lan', 'opt1']
    api.netflow = ['lan', 'opt1']
    api.subnets.append({'uuid': 'sub-99', 'subnet': '10.0.99.0/24', 'description': OWNER_TAG + ' TEST99'})
    api.reservations = [reservation('aa:aa:aa:aa:aa:99', '10.0.99.5', OWNER_TAG)]
    api.reservations[0]['subnet'] = 'sub-99'
    api.rules = [{'uuid': 'f1', 'description': OWNER_TAG + ' VLAN 99: TEST99'},
                 {'uuid': 'f2', 'description': 'hand made'}]
    Reconciler(api, 'apply').run(Intent())
    assert api.paths() == [
        '/api/kea/dhcpv4/set',
        '/api/kea/dhcpv4/del_reservation/r-10.0.99.5',
        '/api/kea/dhcpv4/del_subnet/sub-99',
        '/api/firewall/filter/del_rule/f1',
        '/api/diagnostics/netflow/setconfig',
        '/api/kea/service/reconfigure',
        '/api/firewall/filter/apply',
        '/api/diagnostics/netflow/reconfigure',
        '/api/interfaces/assignment/set_item/opt1',
        '/api/interfaces/assignment/del_item/opt1',
        '/api/interfaces/assignment/reconfigure',
        '/api/interfaces/vlan_settings/del_item/v99',
        '/api/interfaces/vlan_settings/reconfigure',
    ]
    assert dict(api.posts)['/api/kea/dhcpv4/set'] == {'dhcpv4': {'general': {'interfaces': 'lan'}}}


def test_hand_made_vlan_is_used_and_kept():
    api = FakeOPNsense()
    api.vlans = [{'uuid': 'v99', 'if': 'vtnet1', 'tag': '99', 'vlanif': 'vlan0.99', 'descr': 'mine'}]
    Reconciler(api, 'apply').run(intent_from_system_cfg(VLAN_CFG))
    assert '/api/interfaces/vlan_settings/add_item' not in api.paths()
    assert not any('vlan_settings/set_item' in path for path in api.paths())
    assert dict(api.posts)['/api/interfaces/assignment/add_item']['interface']['if'] == 'vlan0.99'


def test_netflow_left_alone_when_off():
    api = FakeOPNsense()
    api.netflow = []
    Reconciler(api, 'apply').run(intent_from_system_cfg(VLAN_CFG))
    assert not any('netflow' in path for path in api.paths())
