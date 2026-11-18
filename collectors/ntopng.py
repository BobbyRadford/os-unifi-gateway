# -*- coding: utf-8 -*-
"""Per-client app traffic from ntopng, reported as a UniFi gateway's DPI
stats (`dpi_stats` in the inform), which fill a client's Traffic Activity
and Insights > Activity in the controller.

ntopng (the os-ntopng plugin) names each connection's application with
nDPI and keeps bytes per host and application. ndpi_apps.json maps nDPI's
names to UniFi's app IDs, (category << 16) | app, and anything it doesn't
know counts as UniFi's Unknown app. dev/make_ndpi_apps.py regenerates it.

Settings, under [ntopng]: `url` (like http://10.0.0.1:3000; unset turns
this off), `user` (default admin) and `password_file`.
"""
import json
import logging
import os
import time

import requests

logger = logging.getLogger('unifi-gateway')

APPS_INTERVAL = 60
INTERFACES_INTERVAL = 300
UNKNOWN_APP = 0xFFFFFF

with open(os.path.join(os.path.dirname(__file__), 'ndpi_apps.json')) as _f:
    NDPI_APPS = json.load(_f)


def unifi_app(ndpi_name):
    """UniFi's (cat, app) for an nDPI application name."""
    app_id = NDPI_APPS.get(ndpi_name, UNKNOWN_APP)
    return app_id >> 16 & 0xFF, app_id & 0xFFFF


class Ntopng:
    """ntopng's REST API, with basic auth."""

    def __init__(self, url, user, password, timeout=5):
        self.url = url.rstrip('/')
        self.auth = (user, password)
        self.timeout = timeout
        self.session = requests.Session()

    @classmethod
    def from_config(cls, config):
        url = config.get('ntopng', 'url', fallback='').strip()
        if not url:
            return None
        password = config.get('ntopng', 'password', fallback='').strip()
        password_file = config.get('ntopng', 'password_file', fallback='').strip()
        if password_file:
            with open(password_file) as f:
                password = f.read().strip()
        return cls(url, config.get('ntopng', 'user', fallback='admin'), password)

    def _get(self, path, **params):
        response = self.session.get(self.url + path, params=params, auth=self.auth,
                                    timeout=self.timeout, allow_redirects=False)
        if response.status_code != 200:
            # a wrong password redirects to the login page
            raise requests.HTTPError('%s: HTTP %d' % (path, response.status_code))
        return response.json().get('rsp')

    def interfaces(self):
        """{device name: ntopng interface id}"""
        return {row['ifname']: row['ifid']
                for row in self._get('/lua/rest/v2/get/ntopng/interfaces.lua') or []}

    def host_apps(self, ifid, ip):
        """{nDPI app name: {'bytes.sent', 'bytes.rcvd', ...}} for a host,
        counted since ntopng first saw it; {} if it hasn't."""
        try:
            host = self._get('/lua/rest/v2/get/host/data.lua', ifid=ifid, host=ip)
        except ValueError:
            return {}
        return (host or {}).get('ndpi') or {}


class AppCounter:
    """Bytes per client and app, {ip: {(cat, app): [tx, rx]}}, as the
    client sees them. They start at zero with the first update and only
    grow: ntopng's own counts restart when it forgets an idle host or
    restarts itself, so each update adds how much they grew."""

    def __init__(self):
        self.totals = {}
        self.started = int(time.time())
        self._last = None

    def update(self, hosts):
        """`hosts` is {ip: Ntopng.host_apps(...)} for the clients read now."""
        first = self._last is None
        last = self._last or {}
        for ip, apps in hosts.items():
            before = last.get(ip, {})
            totals = self.totals.setdefault(ip, {})
            for name, counts in apps.items():
                sent, received = int(counts.get('bytes.sent') or 0), int(counts.get('bytes.rcvd') or 0)
                if first:
                    continue
                was = before.get(name, (0, 0))
                # lower than before: ntopng started counting again from zero
                grew_sent = sent - was[0] if sent >= was[0] else sent
                grew_received = received - was[1] if received >= was[1] else received
                entry = totals.setdefault(unifi_app(name), [0, 0])
                entry[0] += grew_sent
                entry[1] += grew_received
            last_apps = {name: (int(c.get('bytes.sent') or 0), int(c.get('bytes.rcvd') or 0))
                         for name, c in apps.items()}
            last[ip] = last_apps
        self._last = last

    def dpi_stats(self, clients, countries=None):
        """The inform's `dpi_stats` for `clients` ({ip: mac}): per client,
        cumulative bytes per app, and per country ({ip: {iso: [tx, rx]}},
        from traffic.StateCounter). The controller stores how much each grew
        since the last inform. It keys a country's counts by client and app
        but adds them up only per country for the site, so they go on the
        client's Unknown app, which is always there."""
        countries = countries or {}
        stats = []
        unknown = (UNKNOWN_APP >> 16, UNKNOWN_APP & 0xFFFF)
        for ip, mac in sorted(clients.items()):
            apps = dict(self.totals.get(ip) or {})
            by_country = countries.get(ip) or {}
            if not apps and not by_country:
                continue
            if by_country:
                apps.setdefault(unknown, [0, 0])
            entries = []
            for (cat, app), (tx, rx) in sorted(apps.items()):
                entry = {'cat': cat, 'app': app, 'txBytes': tx, 'rxBytes': rx}
                if (cat, app) == unknown and by_country:
                    entry['countries'] = [{'iso': iso, 'txBytes': ctx, 'rxBytes': crx}
                                          for iso, (ctx, crx) in sorted(by_country.items())]
                entries.append(entry)
            stats.append({'mac': mac, 'initialized': self.started, 'stats': entries})
        return stats
