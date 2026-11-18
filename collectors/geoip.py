# -*- coding: utf-8 -*-
"""Country of an IP address, for traffic per country.

The database is DB-IP's free IP to Country Lite (https://db-ip.com, CC BY
4.0: "IP Geolocation by DB-IP"), in MaxMind's MMDB format. It needs no
account, is published monthly and is downloaded in the background into
[geoip] file. MMDBReader reads the format with the standard library only,
since the OPNsense plugin can't install packages.
"""
import datetime
import functools
import gzip
import ipaddress
import logging
import os
import struct
import threading
import time

import requests

logger = logging.getLogger('unifi-gateway')

URL = 'https://download.db-ip.com/free/dbip-country-lite-%s.mmdb.gz'
REFRESH = 30 * 86400
RETRY = 6 * 3600
METADATA_MARKER = b'\xab\xcd\xefMaxMind.com'


class MMDBReader:
    """Looks up IPv4 addresses in an MMDB file (the format's spec:
    https://maxmind.github.io/MaxMind-DB/)."""

    def __init__(self, path):
        with open(path, 'rb') as f:
            self.buf = f.read()
        start = self.buf.rfind(METADATA_MARKER)
        if start < 0:
            raise ValueError('%s is not an MMDB file' % path)
        self.data_start = 0
        meta, _ = self._decode(start + len(METADATA_MARKER), base=start + len(METADATA_MARKER))
        self.node_count = meta['node_count']
        self.record_size = meta['record_size']
        self.node_bytes = self.record_size // 4
        tree_size = self.node_bytes * self.node_count
        self.data_start = tree_size + 16
        # IPv4 addresses sit under ::/96 in an IPv6 tree
        self.ipv4_start = 0
        if meta['ip_version'] == 6:
            node = 0
            for _ in range(96):
                if node >= self.node_count:
                    break
                node = self._record(node, 0)
            self.ipv4_start = node

    def _record(self, node, bit):
        offset = node * self.node_bytes
        b = self.buf[offset:offset + self.node_bytes]
        if self.record_size == 24:
            return int.from_bytes(b[3:6] if bit else b[0:3], 'big')
        if self.record_size == 28:
            if bit:
                return ((b[3] & 0x0F) << 24) | int.from_bytes(b[4:7], 'big')
            return ((b[3] & 0xF0) << 20) | int.from_bytes(b[0:3], 'big')
        return int.from_bytes(b[4:8] if bit else b[0:4], 'big')

    def lookup(self, address):
        """The record for an IPv4 address, or None."""
        node = self.ipv4_start
        bits = int(ipaddress.IPv4Address(address))
        for i in range(32):
            if node >= self.node_count:
                break
            node = self._record(node, (bits >> (31 - i)) & 1)
        if node <= self.node_count:
            return None
        offset = node - self.node_count - 16 + self.data_start
        return self._decode(offset)[0]

    def _decode(self, offset, base=None):
        """(value, offset after it) for the data field at `offset`.
        Pointers are relative to `base`, the data section by default."""
        base = self.data_start if base is None else base
        buf = self.buf
        ctrl = buf[offset]
        offset += 1
        kind = ctrl >> 5
        if kind == 1:  # pointer
            size = (ctrl >> 3) & 0x3
            low = ctrl & 0x7
            if size == 0:
                target = (low << 8) | buf[offset]
            elif size == 1:
                target = ((low << 16) | int.from_bytes(buf[offset:offset + 2], 'big')) + 2048
            elif size == 2:
                target = ((low << 24) | int.from_bytes(buf[offset:offset + 3], 'big')) + 526336
            else:
                target = int.from_bytes(buf[offset:offset + 4], 'big')
            return self._decode(base + target, base)[0], offset + size + 1
        if kind == 0:  # extended type
            kind = 7 + buf[offset]
            offset += 1
        size = ctrl & 0x1F
        if size >= 29:
            extra = size - 28
            value = int.from_bytes(buf[offset:offset + extra], 'big')
            size = (29, 285, 65821)[extra - 1] + value
            offset += extra
        if kind == 2:  # UTF-8 string
            return buf[offset:offset + size].decode('utf-8'), offset + size
        if kind == 3:  # double
            return struct.unpack('>d', buf[offset:offset + 8])[0], offset + 8
        if kind == 4:  # bytes
            return buf[offset:offset + size], offset + size
        if kind in (5, 6, 9, 10):  # unsigned integers
            return int.from_bytes(buf[offset:offset + size], 'big'), offset + size
        if kind == 7:  # map
            result = {}
            for _ in range(size):
                key, offset = self._decode(offset, base)
                result[key], offset = self._decode(offset, base)
            return result, offset
        if kind == 8:  # int32
            return int.from_bytes(buf[offset:offset + size], 'big', signed=True), offset + size
        if kind == 11:  # array
            result = []
            for _ in range(size):
                item, offset = self._decode(offset, base)
                result.append(item)
            return result, offset
        if kind == 14:  # boolean, held in the size
            return bool(size), offset
        if kind == 15:  # float
            return struct.unpack('>f', buf[offset:offset + 4])[0], offset + 4
        raise ValueError('unsupported MMDB data type %d' % kind)


class CountryDB:
    """ISO country codes of public IPv4 addresses. The database downloads
    in the background; until it is there, every lookup is None."""

    def __init__(self, path, refresh=True):
        self.path = path
        self._reader = None
        self._load()
        if refresh:
            threading.Thread(target=self._refresh_loop, name='geoip', daemon=True).start()

    def country(self, address):
        reader = self._reader
        if reader is None:
            return None
        return _lookup(reader, address)

    def _load(self):
        try:
            self._reader = MMDBReader(self.path)
            _lookup.cache_clear()
        except (OSError, ValueError):
            self._reader = None

    def _age(self):
        try:
            return time.time() - os.path.getmtime(self.path)
        except OSError:
            return REFRESH

    def _refresh_loop(self):
        while True:
            if self._reader is None or self._age() >= REFRESH:
                try:
                    self._download()
                    self._load()
                    logger.info('GeoIP: loaded %s', os.path.basename(self.path))
                except (requests.RequestException, OSError, ValueError) as e:
                    logger.warning('GeoIP: could not download the country database: %s', e)
                    time.sleep(RETRY)
                    continue
            time.sleep(max(REFRESH - self._age(), 60))

    def _download(self):
        # this month's file appears in the first days of the month
        today = datetime.date.today()
        last_month = (today.replace(day=1) - datetime.timedelta(days=1))
        for month in (today, last_month):
            response = requests.get(URL % month.strftime('%Y-%m'), timeout=60)
            if response.status_code == 200:
                break
        response.raise_for_status()
        data = gzip.decompress(response.content)
        partial = self.path + '.part'
        with open(partial, 'wb') as f:
            f.write(data)
        MMDBReader(partial)  # reject a broken file before replacing the old one
        os.replace(partial, self.path)


@functools.lru_cache(maxsize=4096)
def _lookup(reader, address):
    try:
        record = reader.lookup(address)
    except ValueError:
        return None
    return ((record or {}).get('country') or {}).get('iso_code')
