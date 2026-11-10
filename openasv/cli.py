"""Command-line interface.

    openasv serve                         start the web UI and API
    openasv scan TARGET [TARGET ...]      scan and print / write a report (CI friendly exit codes)
    openasv import FILE --scope NAME      score results from Nessus, OpenVAS, ZAP, Nuclei, Nmap, testssl.sh
    openasv report SCAN_ID -f pdf         export a stored report
    openasv doctor                        check engines and configuration
    openasv eol-update                    refresh end-of-life data from endoflife.date

Exit codes for scan/import: 0 PASS, 2 FAIL, 3 scan error.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

from . import DISCLAIMER, __version__


def _write(r: dict, fmt: str, out: str | None) -> None:
    from . import report
    if fmt == "pdf":
        if not out:
            sys.exit("--output is required for PDF")
        from .web.app import create_app
        app = create_app()
        with app.test_request_context():
            from flask import render_template
            css = (Path(app.static_folder) / "app.css").read_text(encoding="utf-8")
            html = render_template("report.html", r=r, printing=True, pdf=True, inline_css=css)
        from weasyprint import HTML
        HTML(string=html, base_url=app.static_folder).write_pdf(out)
        print(f"wrote {out}", file=sys.stderr)
        return
    if fmt == "html":
        from .web.app import create_app
        app = create_app()
        with app.test_request_context():
            from flask import render_template
            css = (Path(app.static_folder) / "app.css").read_text(encoding="utf-8")
            text = render_template("report.html", r=r, printing=True, pdf=True, inline_css=css)
    else:
        text = {"json": report.to_json, "csv": report.to_csv, "md": report.to_markdown}[fmt](r)
    if out and out != "-":
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        print(text)


def _scope_named(name: str) -> int:
    from . import db, service
    row = db.one("SELECT id FROM scopes WHERE name=? AND archived=0", (name,))
    return row["id"] if row else service.create_scope(name, {}, "cli")


def cmd_serve(a):
    from .web.app import create_app
    app = create_app()
    from . import worker
    worker.recover()
    try:
        from waitress import serve
        print(f"OpenASV {__version__} listening on http://{a.host}:{a.port}", file=sys.stderr)
        serve(app, host=a.host, port=a.port, threads=8)
    except ImportError:
        app.run(host=a.host, port=a.port, threaded=True)


def cmd_scan(a):
    from . import db, report, service
    if not a.i_am_authorized:
        sys.exit("Refusing to scan: pass --i-am-authorized to confirm you own or are authorized to test every target.")
    db.init()
    sid = _scope_named(a.scope)
    for t in a.targets:
        service.add_component(sid, t, "cli")
    from .targets import parse
    scan_id = service.launch_scan(sid, a.profile, "cli", authorized=True, label=a.label or "CLI scan",
                                  only=[parse(t).value for t in a.targets])
    last = ""
    while True:
        s = db.scan(scan_id)
        cur = next((f"{x['name']} {x['target']} {x['progress']}%" for x in s["stages"] if x["status"] == "running"), "")
        if cur != last and not a.quiet:
            print(f"  … {cur}", file=sys.stderr)
            last = cur
        if s["status"] in ("completed", "failed", "cancelled"):
            break
        time.sleep(2)
    if s["status"] != "completed":
        print(f"scan {scan_id} {s['status']}: {s['error']}", file=sys.stderr)
        sys.exit(3)
    r = report.build(scan_id)
    _write(r, a.format, a.output)
    print(f"OpenASV scan #{scan_id}: {r['ev']['overall']}", file=sys.stderr)
    sys.exit(0 if r["ev"]["overall"] == "PASS" else 2)


def cmd_import(a):
    from . import db, importers, report
    db.init()
    sid = _scope_named(a.scope)
    scan_id = importers.import_file(sid, Path(a.file), "cli", fmt=a.type)
    r = report.build(scan_id)
    _write(r, a.format, a.output)
    sys.exit(0 if r["ev"]["overall"] == "PASS" else 2)


def cmd_report(a):
    from . import db, report
    db.init()
    r = report.build(a.scan_id)
    if not r:
        sys.exit("unknown scan")
    _write(r, a.format, a.output)


def cmd_doctor(a):
    from . import config, worker
    print(f"OpenASV {__version__}\nconfig: {config.settings.config_dir}\ndata:   {config.settings.data_dir}")
    for k, v in worker.tool_versions().items():
        print(f"  {k:12} {v}")
    print(f"  privileged   {config.settings.privileged} (SYN/UDP/OS detection {'enabled' if config.settings.privileged else 'disabled'})")
    print(f"  NVD          {'enabled' if config.settings.nvd_enabled else 'disabled'}"
          f"{' (API key set)' if config.settings.nvd_api_key else ''}")


def cmd_eol_update(a):
    import json

    import requests

    from . import config
    from .engines import eol
    cur = eol.data()
    out = {"generated": time.strftime("%Y-%m-%d"), "source": "https://endoflife.date (MIT)", "products": {}}
    for key, p in cur["products"].items():
        r = requests.get(f"https://endoflife.date/api/{key}.json", timeout=20)
        if r.status_code != 200:
            out["products"][key] = p
            continue
        out["products"][key] = {"title": p["title"], "cpes": p["cpes"], "cycles": [
            {"cycle": str(c.get("cycle")), "eol": c.get("eol"), "latest": c.get("latest"), "support": c.get("support")}
            for c in r.json()]}
        print(f"  {key}: {len(out['products'][key]['cycles'])} cycles", file=sys.stderr)
    dest = config.settings.data_dir / "eol.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(out, indent=1))
    print(f"wrote {dest}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="openasv", description="External vulnerability scanning with ASV-style PCI DSS reporting.",
                                epilog=DISCLAIMER)
    p.add_argument("--version", action="version", version=f"openasv {__version__}")
    p.add_argument("--lang", choices=("en", "vi"), default=os.environ.get("OPENASV_LANG", "en"),
                   help="language of exported HTML/PDF reports (default: en)")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("serve", help="run the web UI and API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=9100)
    s.set_defaults(fn=cmd_serve)

    fmts = ["json", "md", "csv", "html", "pdf"]
    s = sub.add_parser("scan", help="scan targets and report")
    s.add_argument("targets", nargs="+", help="URL, hostname, IP or CIDR")
    s.add_argument("--profile", default="asv")
    s.add_argument("--scope", default="CLI")
    s.add_argument("--label", default="")
    s.add_argument("-f", "--format", choices=fmts, default="md")
    s.add_argument("-o", "--output")
    s.add_argument("-q", "--quiet", action="store_true")
    s.add_argument("--i-am-authorized", action="store_true", help="confirm you are authorized to test the targets")
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("import", help="import and score results from another scanner")
    s.add_argument("file")
    s.add_argument("--scope", default="Imported")
    s.add_argument("--type", choices=["nessus", "gvm", "zap", "nuclei", "nmap", "testssl"])
    s.add_argument("-f", "--format", choices=fmts, default="md")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("report", help="export a stored report")
    s.add_argument("scan_id", type=int)
    s.add_argument("-f", "--format", choices=fmts, default="json")
    s.add_argument("-o", "--output")
    s.set_defaults(fn=cmd_report)

    sub.add_parser("doctor", help="check engines and configuration").set_defaults(fn=cmd_doctor)
    sub.add_parser("eol-update", help="refresh end-of-life data").set_defaults(fn=cmd_eol_update)
    argv = sys.argv[1:] if argv is None else list(argv)
    if not any(x in sub.choices for x in argv) and not any(x in ("-h", "--help", "--version") for x in argv):
        at = 2 if argv[:1] == ["--lang"] else (1 if argv[:1] and argv[0].startswith("--lang=") else 0)
        argv.insert(at, "serve")      # `python -m openasv` (e.g. the IDE Run button) starts the web UI
    a = p.parse_args(argv)
    from . import i18n
    i18n.set_lang(a.lang)
    a.fn(a)


if __name__ == "__main__":
    main()
