#!/usr/bin/env python3
"""Build openasv/data/eol.json from a checkout of https://github.com/endoflife-date/endoflife.date (MIT).

    git clone --depth 1 https://github.com/endoflife-date/endoflife.date /tmp/eol
    python scripts/build_eol_snapshot.py /tmp/eol
"""
import datetime as dt
import json
import sys
from pathlib import Path

import yaml

PRODUCTS = [
    "nginx", "apache-http-server", "tomcat", "php", "python", "nodejs", "openssl", "mysql", "mariadb",
    "postgresql", "mongodb", "redis", "elasticsearch", "haproxy", "exim", "postfix", "windows-server",
    "windows", "ubuntu", "debian", "centos", "rhel", "alpine", "wordpress", "drupal", "django", "laravel",
    "dotnet", "jquery", "jenkins", "grafana", "kibana", "rabbitmq", "memcached", "squid", "spring-boot",
    "spring-framework", "rails", "ruby", "go", "java", "eclipse-jetty", "wildfly", "magento", "joomla",
    "openvpn", "zookeeper", "kafka", "couchdb", "solr", "liferay", "confluence", "jira-software",
    "gitlab", "zabbix", "pfsense", "fortios", "panos", "cisco-ios-xe", "vmware-esxi", "vcenter",
]


def norm(v):
    if isinstance(v, (dt.date, dt.datetime)):
        return v.isoformat()[:10]
    return v


def main(src: str) -> None:
    out = {"generated": dt.date.today().isoformat(), "source": "https://endoflife.date (MIT)", "products": {}}
    for name in PRODUCTS:
        p = Path(src) / "products" / f"{name}.md"
        if not p.exists():
            continue
        fm = yaml.safe_load(p.read_text(encoding="utf-8").split("---")[1])
        cycles = []
        for r in fm.get("releases") or []:
            cycles.append({"cycle": str(r.get("releaseCycle")), "eol": norm(r.get("eol")),
                           "latest": str(r.get("latest") or "") or None,
                           "support": norm(r.get("support"))})
        cpes = [i["cpe"] for i in fm.get("identifiers") or [] if isinstance(i, dict) and "cpe" in i]
        out["products"][name] = {"title": fm.get("title", name), "cpes": cpes, "cycles": cycles}
    dest = Path(__file__).resolve().parent.parent / "openasv" / "data" / "eol.json"
    dest.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {dest} with {len(out['products'])} products")


if __name__ == "__main__":
    main(sys.argv[1])
