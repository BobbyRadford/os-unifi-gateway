import json
import os
import stat

from provision import store_system_cfg


def test_stores_latest_and_history(tmp_path):
    cfg = store_system_cfg(str(tmp_path), json.dumps({'udapi': {'a': 1}}))
    assert cfg == {'udapi': {'a': 1}}
    latest = tmp_path / 'system_cfg.json'
    assert json.loads(latest.read_text()) == cfg
    assert stat.S_IMODE(os.stat(latest).st_mode) == 0o600
    assert len(os.listdir(tmp_path / 'system_cfg-history')) == 1


def test_unchanged_config_adds_no_history(tmp_path):
    store_system_cfg(str(tmp_path), {'udapi': {'a': 1}})
    store_system_cfg(str(tmp_path), json.dumps({'udapi': {'a': 1}}))
    assert len(os.listdir(tmp_path / 'system_cfg-history')) == 1
    store_system_cfg(str(tmp_path), {'udapi': {'a': 2}})
    assert len(os.listdir(tmp_path / 'system_cfg-history')) == 2


def test_rejects_non_json(tmp_path):
    assert store_system_cfg(str(tmp_path), 'not json') is None
    assert not (tmp_path / 'system_cfg.json').exists()
