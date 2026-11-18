import copy

import pytest

from reconcile import (OWNER_TAG, DdnsAccount, DhcpScope, Intent, Network, PortForward, Reconciler,
                       StaticRoute, intent_from_system_cfg)

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


class NotFound(Exception):
    """What the API client raises for a 404, e.g. a plugin that isn't installed."""
    status = 404


class FakeOPNsense:
    """Answers the GETs the reconciler makes and records its POSTs."""

    def __init__(self):
        self.subnets = [{'uuid': SUBNET_UUID, 'subnet': '10.0.0.0/24',
                         'pools': '10.0.0.100 - 10.0.0.254', 'valid_lifetime': '',
                         'option_data.routers': '10.0.0.1'}]
        self.reservations = []
        self.nat = []
        self.hosts = []
        self.lease = '4000'
        self.kea_interfaces = ['lan']
        self.assigned = [{'uuid': 'lan', 'identifier': 'lan', 'if': 'vtnet1',
                          'ipaddr': '10.0.0.1/24', 'enable': '1'}]
        self.vlans = []
        self.rules = []
        self.dnsbl = []
        self.routes = []
        self.gateways = [{'uuid': 'gw-wan', 'name': 'WAN_DHCP', 'gateway': '203.0.113.1', 'ipprotocol': 'inet',
                          'descr': 'Interface WAN_DHCP Gateway'}]
        self.aliases = []
        self.geoip_url = ''
        self.mdns = None            # os-mdns-repeater settings when installed
        self.ddns = None            # os-ddclient accounts when installed
        self.posts = []

    def get(self, path):
        # plugins answer 404 until they are installed
        plugins = {'/api/mdnsrepeater/settings/get': self.mdns and {'mdnsrepeater': self.mdns},
                   '/api/dyndns/accounts/search_item': self.ddns is not None and {'rows': self.ddns}}
        if path in plugins:
            if not plugins[path]:
                raise NotFound()
            return plugins[path]
        general = {'valid_lifetime': self.lease,
                   'interfaces': {i: {'value': i.upper(), 'selected': 1} for i in self.kea_interfaces}}
        return {
            '/api/interfaces/assignment/search_item': {'rows': self.assigned},
            '/api/interfaces/vlan_settings/search_item': {'rows': self.vlans},
            '/api/firewall/filter/search_rule': {'rows': self.rules},
            '/api/kea/dhcpv4/search_subnet': {'rows': self.subnets},
            '/api/kea/dhcpv4/search_reservation': {'rows': self.reservations},
            '/api/kea/dhcpv4/get': {'dhcpv4': {'general': general}},
            '/api/firewall/d_nat/search_rule': {'rows': self.nat},
            '/api/unbound/settings/search_host_override': {'rows': self.hosts},
            '/api/unbound/settings/search_dnsbl': {'rows': self.dnsbl},
            '/api/routes/routes/search_route': {'rows': self.routes},
            '/api/routing/settings/search_gateway': {'rows': self.gateways},
            '/api/firewall/alias/get': {'alias': {'geoip': {'url': self.geoip_url}}},
            '/api/firewall/alias/search_item': {'rows': self.aliases},
            '/api/dyndns/settings/get': {'ddclient': {'general': {'enabled': '1'}}},
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
                                     {'00:00:5e:00:53:70': '10.0.0.112'}, router='10.0.0.1')]
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
        '/api/kea/service/reconfigure',
        '/api/firewall/filter/apply',
    ]
    posts = dict(api.posts)
    assert posts['/api/interfaces/vlan_settings/add_item']['vlan']['if'] == 'vtnet1'
    assert posts['/api/interfaces/assignment/add_item']['interface'] == {
        'if': 'vlan0.99', 'descr': 'TEST99', 'enable': '1', 'type4': 'staticv4', 'ipaddr': '10.0.99.1/24'}
    assert posts['/api/kea/dhcpv4/set'] == {'dhcpv4': {'general': {'interfaces': 'lan,opt1'}}}
    subnet = posts['/api/kea/dhcpv4/add_subnet']['subnet4']
    assert subnet['pools'] == '10.0.99.100 - 10.0.99.200'
    assert subnet['option_data'] == {'routers': '10.0.99.1', 'domain_name_servers': '10.0.99.1',
                                     'ntp_servers': '', 'domain_name': ''}
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
                        'option_data.routers': '10.0.99.1', 'option_data.domain_name_servers': '10.0.99.1',
                        'option_data.ntp_servers': '', 'option_data.domain_name': ''})
    api.kea_interfaces = ['lan', 'opt1']
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
        '/api/kea/service/reconfigure',
        '/api/firewall/filter/apply',
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


def test_isolation_blocks_each_other_network():
    # OPNsense takes one network per API-made rule
    api = FakeOPNsense()
    network = Network(40, 'IoT', '10.0.40.1/24', isolated=True, others=['10.0.0.0/24', '10.0.50.0/24'])
    Reconciler(api, 'apply').run(Intent(networks=[network]))
    rules = [body['rule'] for path, body in api.posts if path == '/api/firewall/filter/add_rule']
    assert sorted((r['action'], r['destination_net']) for r in rules) == [
        ('block', '10.0.0.0/24'), ('block', '10.0.50.0/24'), ('pass', 'any')]


def test_saved_changes_are_applied_when_a_later_step_fails():
    api = FakeOPNsense()
    post = api.post

    def refuse_rules(path, body=None):
        if path == '/api/firewall/filter/add_rule':
            return {'result': 'failed', 'validations': {'rule.destination_net': 'bad'}}
        return post(path, body)
    api.post = refuse_rules
    with pytest.raises(RuntimeError):
        Reconciler(api, 'apply').run(intent_from_system_cfg(VLAN_CFG))
    assert api.paths()[-1] == '/api/kea/service/reconfigure'


# Shapes from the Network 10.6.109 controller's UXG config generator
FEATURES_CFG = {'udapi': {
    'interfaces': VLAN_CFG['udapi']['interfaces'],
    'services': {
        'dhcpServers': [{
            'enabled': True, 'ipVersion': 'v4', 'gatewayAddress': '10.0.99.254', 'ipv4Netmask': 24,
            'dnsServers': ['1.1.1.1', '9.9.9.9'], 'domain': 'lab.internal', 'leaseTime': 86400,
            'name': 'net_TEST99_br99_10-0-99-0-24', 'rangeStart': '10.0.99.100', 'rangeStop': '10.0.99.200',
            'options': [{'optionNumber': 42, 'value': '10.0.99.1,10.0.0.1'}, {'optionNumber': 2, 'value': '3600'}]}],
        'utm': {'enabled': True, 'dnsFilter': [
            {'adsFilter': True, 'dnsAddress': '203.0.113.1', 'netAddresses': ['10.0.99.1/24']},
            {'dnsAddress': '185.228.168.168', 'netAddresses': ['10.0.0.1/24']}]},
        'geoipFiltering': {'enabled': True, 'action': 'block', 'countryList': ['ru', 'CN'],
                           'direction': 'both', 'interfaces': [{'id': 'eth0'}]},
        'mdns': {'enabled': True, 'interfaces': [{'id': 'br0'}, {'id': 'br99'}], 'reflectFilter': []},
        'ddns': {'enabled': True, 'clients': [
            {'hostname': 'home.example.com', 'username': 'bob', 'password': 'pw', 'interface': {'id': 'eth0'},
             'service': 'dyndns'},
            {'hostname': 'www', 'username': 'example.com', 'password': 'pw2', 'interface': {'id': 'eth0'},
             'service': 'custom', 'customName': 'namecheap.0', 'server': 'dynamicdns.park-your-domain.com'},
            {'hostname': 'x.duckdns.org', 'username': 'emptyString', 'password': 'token',
             'interface': {'id': 'eth0'}, 'service': 'duckdns'},
            {'hostname': 'y.example.com', 'username': 'u', 'password': 'p', 'interface': {'id': 'eth0'},
             'service': 'custom', 'server': 'example.com', 'customName': 'example.com'}]},
    },
    'routes/static': [
        {'enabled': True, 'type': 'gateway', 'destination': '0.0.0.0/0', 'gateway': '203.0.113.1',
         'distance': 1, 'table': 201, 'description': 'WAN_DEFAULT_GATEWAY:abc'},
        {'enabled': True, 'type': 'gateway', 'destination': '192.168.5.0/24', 'gateway': '10.0.0.254',
         'distance': 1, 'description': 'STATIC_ROUTE:r1'},
        {'enabled': True, 'type': 'blackhole', 'destination': '198.51.100.0/24', 'distance': 1,
         'description': 'STATIC_ROUTE:r2'},
        {'enabled': True, 'type': 'interface', 'destination': '172.16.0.0/16', 'interface': 'wgsrv1',
         'distance': 1, 'description': 'STATIC_ROUTE:r3'},
    ],
}}


def test_features_from_system_cfg():
    intent = intent_from_system_cfg(FEATURES_CFG)
    scope = intent.dhcp[0]
    assert (scope.router, scope.dns_servers, scope.domain, scope.ntp_servers) == (
        '10.0.99.254', ['1.1.1.1', '9.9.9.9'], 'lab.internal', ['10.0.99.1', '10.0.0.1'])
    # a dnsFilter entry without adsFilter is content filtering, not ad blocking
    assert intent.ad_block == ['10.0.99.0/24']
    assert intent.region_block == {'countries': ['CN', 'RU'], 'direction': 'both'}
    assert intent.mdns == [0, 99]
    # the controller's own routes and interface routes are left out
    assert intent.static_routes == [StaticRoute('192.168.5.0/24', '10.0.0.254'), StaticRoute('198.51.100.0/24')]
    assert intent.ddns == [DdnsAccount('dyndns2', 'home.example.com', 'bob', 'pw'),
                           DdnsAccount('namecheap', 'www', 'example.com', 'pw2'),
                           DdnsAccount('duckdns', 'x.duckdns.org', '', 'token')]


def test_region_blocking_allow_action_is_skipped():
    cfg = copy.deepcopy(FEATURES_CFG)
    cfg['udapi']['services']['geoipFiltering']['action'] = 'allow'
    assert intent_from_system_cfg(cfg).region_block == {}


def test_managed_subnet_gets_unifis_dhcp_options():
    api = FakeOPNsense()
    Reconciler(api, 'apply').run(intent_from_system_cfg(FEATURES_CFG))
    subnet = dict(api.posts)['/api/kea/dhcpv4/add_subnet']['subnet4']
    assert subnet['option_data'] == {'routers': '10.0.99.254', 'domain_name_servers': '1.1.1.1,9.9.9.9',
                                     'ntp_servers': '10.0.99.1,10.0.0.1', 'domain_name': 'lab.internal'}


def test_hand_made_subnet_only_gets_options_unifi_sets():
    api = FakeOPNsense()
    api.subnets[0].update({'option_data_autocollect': '1', 'option_data.domain_name_servers': '10.0.0.1',
                           'option_data.ntp_servers': '10.0.0.1', 'option_data.domain_name': ''})
    scope = DhcpScope('10.0.0.0/24', '10.0.0.100', '10.0.0.254', 4000, router='10.0.0.1',
                      dns_servers=['10.0.0.1'], domain='internal')
    api.lease = '4000'
    Reconciler(api, 'apply').run(Intent(dhcp=[scope]))
    # the NTP server UniFi doesn't set is kept
    assert api.posts[0] == ('/api/kea/dhcpv4/set_subnet/' + SUBNET_UUID, {'subnet4': {
        'option_data_autocollect': '0',
        'option_data': {'routers': '10.0.0.1', 'domain_name_servers': '10.0.0.1', 'domain_name': 'internal'}}})


def test_ad_blocking_is_one_blocklist():
    api = FakeOPNsense()
    api.dnsbl = [{'uuid': 'b0', 'description': 'hand made', 'enabled': '1'}]
    Reconciler(api, 'apply').run(Intent(ad_block=['10.0.40.0/24', '10.0.99.0/24']))
    assert api.posts == [
        ('/api/unbound/settings/add_dnsbl', {'blocklist': {
            'enabled': '1', 'type': 'ag', 'source_nets': '10.0.40.0/24,10.0.99.0/24',
            'description': OWNER_TAG + ' Ad blocking for 10.0.40.0/24, 10.0.99.0/24'}}),
        ('/api/unbound/service/dnsbl', {}),
    ]
    api.dnsbl.append({'uuid': 'b1', 'enabled': '1', 'description': api.posts[0][1]['blocklist']['description']})
    api.posts = []
    assert Reconciler(api, 'apply').run(Intent(ad_block=['10.0.40.0/24', '10.0.99.0/24'])) == []
    Reconciler(api, 'apply').run(Intent())
    assert api.paths() == ['/api/unbound/settings/del_dnsbl/b1', '/api/unbound/service/dnsbl']


def test_static_routes_find_or_add_their_gateway():
    api = FakeOPNsense()
    routes = [StaticRoute('192.168.5.0/24', '10.0.0.254'), StaticRoute('198.51.100.0/24'),
              StaticRoute('192.168.6.0/24', '203.0.113.1'), StaticRoute('192.168.7.0/24', '172.16.0.1')]
    Reconciler(api, 'apply').run(Intent(static_routes=routes))
    assert api.paths() == [
        '/api/routing/settings/add_gateway',
        '/api/routing/settings/reconfigure',
        '/api/routes/routes/add_route',
        '/api/routes/routes/add_route',
        '/api/routes/routes/add_route',
        '/api/routes/routes/reconfigure',
    ]
    assert api.posts[0][1]['gateway_item']['name'] == 'UNIFI_10_0_0_254'
    assert api.posts[0][1]['gateway_item']['interface'] == 'lan'
    added = {body['route']['network']: body['route']['gateway'] for path, body in api.posts
             if path.endswith('add_route')}
    # 172.16.0.1 is on no interface, so its route is skipped
    assert added == {'192.168.5.0/24': 'UNIFI_10_0_0_254', '198.51.100.0/24': 'Null4',
                     '192.168.6.0/24': 'WAN_DHCP'}


def test_removed_static_route_takes_its_gateway_along():
    api = FakeOPNsense()
    api.gateways.append({'uuid': 'gw1', 'name': 'UNIFI_10_0_0_254', 'gateway': '10.0.0.254',
                         'ipprotocol': 'inet', 'descr': OWNER_TAG + ' next hop'})
    api.routes = [{'uuid': 'rt1', 'network': '192.168.5.0/24', 'gateway': 'UNIFI_10_0_0_254', 'enabled': '1',
                   'descr': OWNER_TAG + ' static route from UniFi'},
                  {'uuid': 'rt2', 'network': '192.168.8.0/24', 'gateway': 'WAN_DHCP', 'enabled': '1',
                   'descr': 'hand made'}]
    Reconciler(api, 'apply').run(Intent())
    assert api.paths() == ['/api/routes/routes/del_route/rt1', '/api/routing/settings/del_gateway/gw1',
                           '/api/routing/settings/reconfigure', '/api/routes/routes/reconfigure']


def test_plugins_that_are_missing_are_skipped():
    api = FakeOPNsense()
    intent = Intent(mdns=[0, 99], ddns=[DdnsAccount('dyndns2', 'home.example.com', 'bob', 'pw')])
    assert Reconciler(api, 'apply').run(intent) == []
    assert api.posts == []


def test_mdns_repeater_follows_unifi():
    api = FakeOPNsense()
    api.mdns = {'enabled': '0', 'interfaces': {'lan': {'value': 'LAN', 'selected': 1},
                                               'opt1': {'value': 'TEST99', 'selected': 0}}}
    Reconciler(api, 'apply').run(intent_from_system_cfg(FEATURES_CFG))
    assert dict(api.posts)['/api/mdnsrepeater/settings/set'] == {
        'mdnsrepeater': {'enabled': '1', 'interfaces': 'lan,opt1'}}
    assert '/api/mdnsrepeater/service/reconfigure' in api.paths()
    # one network has nothing to repeat to
    api = FakeOPNsense()
    api.mdns = {'enabled': '1', 'interfaces': 'lan,opt1'}
    Reconciler(api, 'apply').run(Intent(mdns=[0]))
    assert api.posts == [('/api/mdnsrepeater/settings/set', {'mdnsrepeater': {'enabled': '0'}}),
                         ('/api/mdnsrepeater/service/reconfigure', {})]


def test_ddns_accounts_follow_unifi():
    api = FakeOPNsense()
    api.ddns = [{'uuid': 'd0', 'description': 'hand made', 'enabled': '1'}]
    account = DdnsAccount('dyndns2', 'home.example.com', 'bob', 'pw')
    Reconciler(api, 'apply').run(Intent(ddns=[account]))
    path, body = api.posts[0]
    assert path == '/api/dyndns/accounts/add_item'
    assert body['account']['description'].startswith(OWNER_TAG + ' DDNS dyndns2 home.example.com #')
    assert (body['account']['username'], body['account']['password']) == ('bob', 'pw')
    assert api.paths()[-1] == '/api/dyndns/service/reconfigure'

    api.ddns.append(dict(body['account'], uuid='d1'))
    api.posts = []
    assert Reconciler(api, 'apply').run(Intent(ddns=[account])) == []
    # a new password changes the description's hash
    Reconciler(api, 'apply').run(Intent(ddns=[DdnsAccount('dyndns2', 'home.example.com', 'bob', 'new')]))
    assert api.paths() == ['/api/dyndns/accounts/set_item/d1', '/api/dyndns/service/reconfigure']
    api.posts = []
    Reconciler(api, 'apply').run(Intent())
    assert api.paths() == ['/api/dyndns/accounts/del_item/d1', '/api/dyndns/service/reconfigure']


def test_region_blocking_needs_a_geoip_source():
    api = FakeOPNsense()
    assert Reconciler(api, 'apply').run(Intent(region_block={'countries': ['CN'], 'direction': 'both'})) == []
    assert api.posts == []


def test_region_blocking_builds_alias_then_rules():
    api = FakeOPNsense()
    api.geoip_url = 'https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip'
    Reconciler(api, 'apply').run(intent_from_system_cfg(FEATURES_CFG))
    region = [(path, body) for path, body in api.posts
              if '/alias/' in path or 'Region' in str(body) or path.endswith('/filter/apply')]
    assert [path for path, _ in region] == [
        '/api/firewall/alias/add_item',
        '/api/firewall/filter/add_rule',
        '/api/firewall/filter/add_rule',
        '/api/firewall/d_nat/add_rule',
        '/api/firewall/filter/apply',
        '/api/firewall/alias/reconfigure',
    ]
    alias = region[0][1]['alias']
    assert (alias['type'], alias['content']) == ('geoip', 'CN\nRU')
    incoming, outgoing = region[1][1]['rule'], region[2][1]['rule']
    assert (incoming['interface'], incoming['source_net'], incoming['destination_net']) == ('', 'unifi_region_block', 'any')
    assert (outgoing['source_net'], outgoing['destination_net']) == ('any', 'unifi_region_block')
    assert incoming['log'] == outgoing['log'] == '1'
    nat = region[3][1]['rule']
    assert (nat['nordr'], nat['source']['network']) == ('1', 'unifi_region_block')


def test_region_blocking_turns_on_logging_for_an_existing_rule():
    api = FakeOPNsense()
    api.geoip_url = 'https://example.com/geoip.zip'
    api.aliases = [{'uuid': 'a1', 'name': 'unifi_region_block', 'content': 'AF', 'enabled': '1',
                    'description': OWNER_TAG + ' Region blocking'}]
    api.rules = [dict(Reconciler._region_rules('outgoing')[0]['outgoing'], uuid='f1', log='0')]
    Reconciler(api, 'apply').run(Intent(region_block={'countries': ['AF'], 'direction': 'outgoing'}))
    assert api.paths()[0] == '/api/firewall/filter/set_rule/f1'
    assert api.posts[0][1]['rule']['log'] == '1'


def test_region_blocking_off_removes_it_and_port_forwards_keep_its_nat_rule():
    api = FakeOPNsense()
    api.geoip_url = 'https://example.com/geoip.zip'
    api.aliases = [{'uuid': 'a1', 'name': 'unifi_region_block', 'content': 'CN,RU', 'enabled': '1',
                    'description': OWNER_TAG + ' Region blocking'}]
    api.rules = [{'uuid': 'f1', 'description': OWNER_TAG + ' Region blocking incoming'}]
    api.nat = [{'uuid': 'n1', 'descr': OWNER_TAG + ' Region blocking of port forwards', 'nordr': '1'}]
    region = {'countries': ['CN', 'RU'], 'direction': 'incoming'}
    api.rules[0].update(Reconciler._region_rules('incoming')[0]['incoming'])
    assert Reconciler(api, 'apply').run(Intent(region_block=region)) == []
    Reconciler(api, 'apply').run(Intent())
    assert api.paths() == ['/api/firewall/d_nat/del_rule/n1', '/api/firewall/filter/del_rule/f1',
                           '/api/firewall/alias/del_item/a1', '/api/firewall/alias/reconfigure',
                           '/api/firewall/filter/apply']
