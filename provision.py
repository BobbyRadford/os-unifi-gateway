"""The controller's configuration for this gateway, as it pushes it.

A UXG gets its whole configuration as one UDAPI JSON document, `system_cfg`,
in a `setparam`. It always arrives complete, so the latest one is the
controller's full intent. `store_system_cfg` keeps the latest copy in
`system_cfg.json` and every distinct version under `system_cfg-history/`, so
the changes a UI action makes can be read as a diff between two files.

The document holds the site's secrets (Wi-Fi keys, RADIUS secrets, the site
token), so every file is written readable by the owner only.
"""
import hashlib
import json
import logging
import os
import time

logger = logging.getLogger('unifi-gateway')


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def store_system_cfg(directory, value):
    """Save a pushed system_cfg (a JSON string or an already parsed dict) and
    return it parsed, or None when it isn't valid JSON."""
    try:
        cfg = json.loads(value) if isinstance(value, str) else value
    except ValueError:
        logger.warning('Ignoring a system_cfg that is not JSON')
        return None
    if not isinstance(cfg, dict):
        return None

    text = json.dumps(cfg, indent=1, sort_keys=True)
    latest = os.path.join(directory, 'system_cfg.json')
    try:
        with open(latest) as f:
            if f.read() == text:
                return cfg
    except OSError:
        pass

    history = os.path.join(directory, 'system_cfg-history')
    os.makedirs(history, mode=0o700, exist_ok=True)
    digest = hashlib.sha256(text.encode()).hexdigest()[:8]
    name = time.strftime('%Y%m%dT%H%M%S') + '-' + digest + '.json'
    _write_private(os.path.join(history, name), text)
    _write_private(latest, text)
    logger.info('Controller pushed a new system_cfg (%s)', name)
    return cfg
