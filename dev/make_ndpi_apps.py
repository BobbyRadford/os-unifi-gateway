"""Writes collectors/ndpi_apps.json, which maps ntopng's nDPI application
names to UniFi DPI app IDs ((category << 16) | app).

Usage: python3 dev/make_ndpi_apps.py <ruleMap.json> <ntopng-apps.json>

ruleMap.json is the controller's app list (dpi/tdts/ruleMap.json inside
ace.jar). ntopng-apps.json is the `rsp` list of ntopng's
/lua/rest/v2/get/l7/application/consts.lua. Names match when they are equal
ignoring case and punctuation; OVERRIDES covers common apps named
differently. Apps without a match count as UniFi's "Unknown".
"""
import json
import re
import sys

# nDPI name -> UniFi app name
OVERRIDES = {
    'TLS': 'SSL/TLS',
    'Apple': 'Apple.com',
    'AppleiCloud': 'iCloud',
    'AppleiTunes': 'iTunes/App Store',
    'AppleTVPlus': 'Apple TV+',
    'Microsoft': 'Microsoft.com',
    'Microsoft365': 'Microsoft Office 365',
    'Teams': 'Microsoft Teams',
    'Outlook': 'Outlook.com',
    'GoogleServices': 'Google',
    'YouTubeUpload': 'Youtube',
    'YouTubeKids': 'Youtube',
    'WhatsAppCall': 'WhatsApp',
    'WhatsAppFiles': 'WhatsApp',
    'Steam': 'Valve Steam',
    'Playstation': 'Sony PlayStation',
    'NTP': 'Network Time Protocol',
    'SSH': 'Secure Shell (SSH)',
    'MDNS': 'Multicast DNS',
    'DHCP': 'Dynamic Host Configuration Protocol (DHCP)',
    'Akamai': 'Akamai.net',
    'Ookla': 'Speedtest.net',
}


def norm(name):
    return re.sub(r'[^a-z0-9]', '', name.lower())


def main(rule_map, ndpi_apps):
    unifi = json.load(open(rule_map))['applications']
    by_name = {}
    for app_id, app in sorted(unifi.items(), key=lambda item: int(item[0])):
        by_name.setdefault(norm(app['name']), int(app_id))
    mapping = {}
    for app in json.load(open(ndpi_apps)):
        name = app['name']
        app_id = by_name.get(norm(OVERRIDES.get(name, name)))
        if app_id is not None:
            mapping[name] = app_id
    missing = [n for n, u in OVERRIDES.items() if norm(u) not in by_name]
    if missing:
        sys.exit('overrides name no UniFi app: %s' % ', '.join(missing))
    with open('collectors/ndpi_apps.json', 'w') as f:
        json.dump(dict(sorted(mapping.items())), f, indent=0)
        f.write('\n')
    print('%d nDPI apps mapped' % len(mapping))


if __name__ == '__main__':
    main(*sys.argv[1:3])
