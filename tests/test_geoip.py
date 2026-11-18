
from collectors.geoip import METADATA_MARKER, MMDBReader, _lookup

def encode(value):
    """MMDB data encoding for the types the reader needs here."""
    def ctrl(kind, size):
        if kind > 7:
            return bytes([size, kind - 7])
        return bytes([(kind << 5) | size])
    if isinstance(value, str):
        data = value.encode()
        return ctrl(2, len(data)) + data
    if isinstance(value, dict):
        out = ctrl(7, len(value))
        for key, item in value.items():
            out += encode(key) + encode(item)
        return out
    if isinstance(value, int):
        data = value.to_bytes(4, 'big')
        return ctrl(6, len(data)) + data
    raise TypeError(value)

def build(path, network, prefix, record):
    """An IPv4 database (24-bit records) holding one network."""
    nodes = prefix
    bits = int.from_bytes(bytes(int(o) for o in network.split('.')), 'big')
    tree = b''
    for i in range(nodes):
        bit = (bits >> (31 - i)) & 1
        nxt = i + 1 if i + 1 < nodes else nodes + 16  # the last points at data offset 0
        left, right = (nodes, nxt) if bit else (nxt, nodes)
        tree += left.to_bytes(3, 'big') + right.to_bytes(3, 'big')
    meta = {'node_count': nodes, 'record_size': 24, 'ip_version': 4}
    path.write_bytes(tree + bytes(16) + encode(record) + METADATA_MARKER + encode(meta))

def test_reads_a_country(tmp_path):
    db = tmp_path / 'db.mmdb'
    build(db, '81.2.69.0', 24, {'country': {'iso_code': 'GB'}})
    reader = MMDBReader(str(db))
    assert _lookup(reader, '81.2.69.142') == 'GB'
    assert _lookup(reader, '81.2.70.1') is None
    assert _lookup(reader, '8.8.8.8') is None
