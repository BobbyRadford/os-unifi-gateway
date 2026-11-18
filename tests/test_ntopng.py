import configparser

from collectors.ntopng import UNKNOWN_APP, AppCounter, Ntopng, unifi_app


def apps(**counts):
    return {name: {'bytes.sent': sent, 'bytes.rcvd': rcvd} for name, (sent, rcvd) in counts.items()}


def test_unifi_app_ids():
    assert unifi_app('YouTube') == (4, 112)
    assert unifi_app('TLS') == (20, 185)
    assert unifi_app('NoSuchApp') == (UNKNOWN_APP >> 16, UNKNOWN_APP & 0xFFFF) == (255, 0xFFFF)


def test_counts_growth_and_survives_ntopng_restarts():
    counter = AppCounter()
    counter.update({'10.0.0.5': apps(YouTube=(100, 5000))})
    assert counter.totals == {'10.0.0.5': {}}
    counter.update({'10.0.0.5': apps(YouTube=(150, 8000), TLS=(10, 20))})
    assert counter.totals['10.0.0.5'] == {(4, 112): [50, 3000], (20, 185): [10, 20]}
    # ntopng forgot the host and counts from zero again
    counter.update({'10.0.0.5': apps(YouTube=(5, 70))})
    assert counter.totals['10.0.0.5'][(4, 112)] == [55, 3070]


def test_a_client_seen_later_counts_in_full():
    counter = AppCounter()
    counter.update({})
    counter.update({'10.0.40.7': apps(Unknown=(3, 4), Mystery=(1, 1))})
    assert counter.totals['10.0.40.7'] == {(255, 0xFFFF): [4, 5]}


def test_dpi_stats_payload():
    counter = AppCounter()
    counter.started = 1000
    counter.update({})
    counter.update({'10.0.0.5': apps(YouTube=(1, 2)), '10.0.0.6': apps()})
    assert counter.dpi_stats({'10.0.0.5': 'aa:bb', '10.0.0.6': 'cc:dd', '10.0.0.7': 'ee:ff'}) == [
        {'mac': 'aa:bb', 'initialized': 1000,
         'stats': [{'cat': 4, 'app': 112, 'txBytes': 1, 'rxBytes': 2}]}]


def test_from_config(tmp_path):
    config = configparser.RawConfigParser()
    config.read_dict({'ntopng': {}})
    assert Ntopng.from_config(config) is None
    password = tmp_path / 'pw'
    password.write_text('secret\n')
    config.read_dict({'ntopng': {'url': 'http://10.0.0.1:3000/', 'password_file': str(password)}})
    ntopng = Ntopng.from_config(config)
    assert (ntopng.url, ntopng.auth) == ('http://10.0.0.1:3000', ('admin', 'secret'))


def test_countries_ride_on_the_unknown_app():
    counter = AppCounter()
    counter.started = 1000
    counter.update({})
    counter.update({'10.0.0.5': apps(YouTube=(1, 2))})
    stats = counter.dpi_stats({'10.0.0.5': 'aa:bb', '10.0.0.6': 'cc:dd'},
                              {'10.0.0.5': {'US': [5, 50]}, '10.0.0.6': {'DE': [1, 9], 'US': [2, 3]}})
    assert stats == [
        {'mac': 'aa:bb', 'initialized': 1000, 'stats': [
            {'cat': 4, 'app': 112, 'txBytes': 1, 'rxBytes': 2},
            {'cat': 255, 'app': 0xFFFF, 'txBytes': 0, 'rxBytes': 0,
             'countries': [{'iso': 'US', 'txBytes': 5, 'rxBytes': 50}]}]},
        {'mac': 'cc:dd', 'initialized': 1000, 'stats': [
            {'cat': 255, 'app': 0xFFFF, 'txBytes': 0, 'rxBytes': 0,
             'countries': [{'iso': 'DE', 'txBytes': 1, 'rxBytes': 9},
                           {'iso': 'US', 'txBytes': 2, 'rxBytes': 3}]}]},
    ]
