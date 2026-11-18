"""Writes app_domains.json, the domains to block for each UniFi DPI app ID
((category << 16) | app) when a UniFi traffic rule blocks that app.

Usage: python3 dev/make_app_domains.py <ndpi_content_match.c.inc>

The .inc file is nDPI's src/lib/ndpi_content_match.c.inc, from the nDPI
version OPNsense's ntopng uses. Its host_match[] patterns are matched against
the names nDPI sees. collectors/ndpi_apps.json maps the nDPI apps to UniFi
IDs. A pattern ending in a dot ("youtube.") matches any top-level domain in
nDPI, so it becomes the .com domain, and patterns that aren't whole domain
names ("fbcdn-", "wx.") are skipped.
"""
import json
import re
import sys


def domain(pattern):
    """The DNS name to block for an nDPI host pattern, or None."""
    name = pattern.lstrip('.')
    if name.endswith('.'):
        name = name[:-1]
        if '.' not in name:
            if len(name) < 4:
                return None
            name += '.com'
    if '.' not in name or not re.fullmatch(r'[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+', name):
        return None
    return name


def main(content_match):
    source = open(content_match).read()
    start = source.index('host_match[]')
    patterns = re.findall(r'\{\s*"([^"]*)"\s*,\s*"([^"]*)"', source[start:source.index('};', start)])
    unifi_ids = json.load(open('collectors/ndpi_apps.json'))
    apps = {}
    for pattern, ndpi_name in patterns:
        app_id, name = unifi_ids.get(ndpi_name), domain(pattern)
        if app_id is None or name is None:
            continue
        app = apps.setdefault(str(app_id), {'name': ndpi_name, 'domains': set()})
        if len(ndpi_name) < len(app['name']):
            app['name'] = ndpi_name             # "YouTube" rather than "YouTubeKids"
        app['domains'].add(name)
    out = {key: {'name': app['name'], 'domains': sorted(app['domains'])}
           for key, app in sorted(apps.items(), key=lambda item: int(item[0]))}
    with open('app_domains.json', 'w') as f:
        json.dump(out, f, indent=0)
        f.write('\n')
    print('%d UniFi apps with domains' % len(out))


if __name__ == '__main__':
    main(sys.argv[1])
