"""Runtime settings (environment variables) and policy files (YAML)."""
from __future__ import annotations

import hashlib
import json
import os
from functools import lru_cache
from pathlib import Path

import yaml

PKG_DIR = Path(__file__).resolve().parent
ROOT_DIR = PKG_DIR.parent


def _load_dotenv() -> None:
    """Read ``.env`` next to the source tree so `python -m openasv` works from an IDE without extra setup.
    Variables already present in the environment win."""
    p = ROOT_DIR / ".env"
    if not p.is_file():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    if os.environ.get("ZAP_API_KEY"):     # the name docker-compose.yml uses
        os.environ.setdefault("OPENASV_ZAP_API_KEY", os.environ["ZAP_API_KEY"])


_load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(f"OPENASV_{name}", default).strip()


def _flag(name: str, default: bool = False) -> bool:
    v = _env(name, "1" if default else "0").lower()
    return v in ("1", "true", "yes", "on")


class Settings:
    """Read lazily so tests and the CLI can override environment variables at runtime."""

    @property
    def config_dir(self) -> Path:
        return Path(_env("CONFIG_DIR") or ROOT_DIR / "config")

    @property
    def data_dir(self) -> Path:
        return Path(_env("DATA_DIR") or ROOT_DIR / "data")

    # engines
    nmap = property(lambda s: _env("NMAP", "nmap"))
    testssl = property(lambda s: _env("TESTSSL", "testssl.sh"))
    nuclei = property(lambda s: _env("NUCLEI", "nuclei"))
    ssh_audit = property(lambda s: _env("SSH_AUDIT", "ssh-audit"))
    wafw00f = property(lambda s: _env("WAFW00F", "wafw00f"))
    nuclei_templates = property(lambda s: _env("NUCLEI_TEMPLATES"))
    nuclei_interactsh = property(lambda s: _flag("NUCLEI_INTERACTSH", False))
    zap_api = property(lambda s: _env("ZAP_API", "http://127.0.0.1:8090").rstrip("/"))
    zap_api_key = property(lambda s: _env("ZAP_API_KEY"))
    privileged = property(lambda s: _flag("PRIVILEGED", os.geteuid() == 0 if hasattr(os, "geteuid") else False))
    extra_ca = property(lambda s: [x.strip() for x in _env("EXTRA_CA").split(",") if x.strip()])
    localhost_alias = property(lambda s: _env("LOCALHOST_ALIAS"))
    nvd_api_key = property(lambda s: _env("NVD_API_KEY"))
    nvd_enabled = property(lambda s: _flag("NVD", True))
    eol_online = property(lambda s: _flag("EOL_ONLINE", False))
    dns_resolver = property(lambda s: _env("DNS_RESOLVER"))
    # web app
    secret_key = property(lambda s: _env("SECRET_KEY"))
    admin_password = property(lambda s: _env("ADMIN_PASSWORD"))
    api_token = property(lambda s: _env("API_TOKEN"))
    webhook_url = property(lambda s: _env("WEBHOOK_URL"))
    base_url = property(lambda s: _env("BASE_URL", "http://localhost:9100").rstrip("/"))
    scheduler = property(lambda s: _flag("SCHEDULER", True))
    # identity of the party running the scan (report section A.2)
    scanner_company = property(lambda s: _env("SCANNER_COMPANY"))
    scanner_contact = property(lambda s: _env("SCANNER_CONTACT"))
    scanner_email = property(lambda s: _env("SCANNER_EMAIL"))
    scanner_website = property(lambda s: _env("SCANNER_WEBSITE"))


settings = Settings()


def _load(name: str):
    p = settings.config_dir / name
    with open(p, encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


@lru_cache(maxsize=None)
def policy() -> dict:
    return _load("policy.yaml")


@lru_cache(maxsize=None)
def policy_hash() -> str:
    raw = json.dumps(policy(), sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()[:12]


@lru_cache(maxsize=None)
def profiles() -> dict:
    return _load("profiles.yaml")


@lru_cache(maxsize=None)
def pci() -> dict:
    return _load("pci-dss.yaml")


def target_policy() -> dict:
    """Not cached: operators may edit it while the service runs."""
    return _load("target-policy.yaml")


def reload() -> None:
    for fn in (policy, policy_hash, profiles, pci):
        fn.cache_clear()


def category(name: str) -> dict:
    cats = policy()["categories"]
    return cats.get(name) or cats["other_web"]
