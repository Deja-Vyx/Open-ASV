import os
import shutil
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
FIX = Path(__file__).parent / "fixtures"


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    """Each test gets its own data dir and a copy of the default config."""
    cfg = tmp_path / "config"
    shutil.copytree(ROOT / "config", cfg)
    monkeypatch.setenv("OPENASV_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("OPENASV_CONFIG_DIR", str(cfg))
    monkeypatch.setenv("OPENASV_SCHEDULER", "0")
    monkeypatch.setenv("OPENASV_NVD", "0")
    from openasv import config, db
    config.reload()
    db.init()
    yield cfg
    config.reload()


@pytest.fixture
def fix():
    return FIX


def make_ctx(host="shop.example.com", tool_host=None, urls=None):
    import threading

    from openasv.engines.base import Ctx, HostTarget
    t = HostTarget(host=host, tool_host=tool_host or host, ips=["127.0.0.1"], web_urls=list(urls or []),
                   ports=[443])
    return Ctx(scan_id=1, run_dir=Path(tempfile.mkdtemp()), target=t, profile={"nmap": {}},
               scope_domains=["example.com"], log=lambda s: None, progress=lambda *a: None, cancel=threading.Event())


os.environ.setdefault("OPENASV_SCHEDULER", "0")
