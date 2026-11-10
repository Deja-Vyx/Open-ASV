"""Every page renders; CSRF, authorization and API token rules hold."""
import json
import re

from openasv import db, findings, service


def _client():
    from openasv.web.app import create_app
    app = create_app()
    app.config["TESTING"] = True
    return app.test_client()


def _csrf(c, path="/"):
    return re.search(r'name="csrf" value="([^"]+)"', c.get(path).get_data(as_text=True)).group(1)


def _seed():
    sid = service.create_scope("Online store", {"company": "Example Retail"}, "t", ["https://localhost:8443/"])
    fs = [findings.make("zap", "sql_injection", "localhost", "SQL Injection", port=8443, url="https://localhost:8443/s?q=1", param="q"),
          findings.make("nmap", "open_port", "localhost", "8443/tcp https", port=8443),
          findings.make("testssl", "ssl_early_tls", "localhost", "TLS 1.0 offered", port=8443),
          findings.make("zap", "missing_security_header", "localhost", "CSP not set", port=8443, url="https://localhost:8443/")]
    scan_id = db.x("INSERT INTO scans (scope_id,created_at,started_at,finished_at,status,profile,components,authorized_by,"
                   "authorization,meta,result) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                   (sid, db.now(), db.now(), db.now(), "completed", "asv",
                    json.dumps([{"value": "https://localhost:8443/", "kind": "url", "host": "localhost"}]), "t", "ok",
                    json.dumps({"versions": {"nmap": "7.94"}, "discovered": [{"value": "www.example.com", "kind": "host",
                                                                              "reason": "MX", "status": "discovered"}]}), "FAIL"))
    db.save_findings(scan_id, findings.consolidate(fs))
    db.save_notes(scan_id, [{"key": "n1", "type": "remote_access", "component": "localhost", "port": 22, "detail": "ssh", "source": "nmap"}])
    db.upsert_component(sid, "host", "www.example.com", status="discovered", source="discovered", reason="MX")
    return sid, scan_id


def test_pages_render():
    c = _client()
    sid, scan_id = _seed()
    fkey = db.findings(scan_id)[0]["key"]
    for path in ["/", "/scopes", f"/scopes/{sid}", f"/scopes/{sid}?tab=discovered", f"/scopes/{sid}?tab=scans",
                 f"/scopes/{sid}?tab=settings", f"/scopes/{sid}/scan", "/scans", f"/scans/{scan_id}",
                 f"/scans/{scan_id}/status.json", f"/scans/{scan_id}/report", f"/scans/{scan_id}/report?print=1",
                 f"/scans/{scan_id}/findings", f"/scans/{scan_id}/findings?f={fkey}", f"/scans/{scan_id}/findings?status=Fail",
                 f"/scans/{scan_id}/finalize", "/disputes", "/disputes?status=all", "/import", "/settings",
                 f"/scopes/{sid}/combine", f"/scopes/{sid}/combine?scan={scan_id}",
                 f"/scans/{scan_id}/report.json", f"/scans/{scan_id}/report.csv", f"/scans/{scan_id}/report.md", "/healthz"]:
        r = c.get(path)
        assert r.status_code == 200, (path, r.status_code, r.get_data(as_text=True)[:400])
    body = c.get(f"/scans/{scan_id}/report").get_data(as_text=True)
    assert "not a PCI SSC Approved Scanning Vendor" in body and "automatic failure" in body
    assert "Content-Security-Policy" in c.get("/").headers


def test_post_requires_csrf_and_authorization():
    c = _client()
    sid, _ = _seed()
    assert c.post("/scopes", data={"name": "x"}).status_code == 400
    tok = _csrf(c)
    r = c.post(f"/scopes/{sid}/scans", data={"csrf": tok, "profile": "quick"}, follow_redirects=True)
    assert "authorized" in r.get_data(as_text=True)


def test_dispute_and_declaration_via_ui():
    c = _client()
    _, scan_id = _seed()
    tok = _csrf(c)
    fkey = next(f["key"] for f in db.findings(scan_id) if f["category"] == "sql_injection")
    r = c.post(f"/scans/{scan_id}/disputes", data={"csrf": tok, "fkey": fkey, "kind": "false_positive", "attested": "yes",
                                                   "justification": "Input is validated as integer; manual replay returns 400."},
               follow_redirects=True)
    assert r.status_code == 200 and "pending" in r.get_data(as_text=True)
    did = db.one("SELECT id FROM disputes")["id"]
    c.post(f"/disputes/{did}/review", data={"csrf": tok, "decision": "accepted", "reviewer": "QA", "notes": "Replayed, not exploitable."})
    assert db.one("SELECT status FROM disputes")["status"] == "accepted"
    c.post(f"/scans/{scan_id}/declarations", data={"csrf": tok, "nkey": "n1", "option": "justified",
                                                   "statement": "SSH allowed only from the admin VPN with MFA."})
    assert db.declarations(scan_id)["n1"]["option"] == "justified"


def test_api_token(monkeypatch):
    monkeypatch.setenv("OPENASV_API_TOKEN", "s3cret")
    c = _client()
    assert c.get("/api/v1/scopes").status_code == 401
    r = c.post("/api/v1/scopes", json={"name": "API scope", "components": ["10.0.0.5"]}, headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 201
    r = c.get("/api/v1/scopes", headers={"Authorization": "Bearer s3cret"})
    assert r.json[0]["name"] == "API scope"
    r = c.post(f"/api/v1/scopes/{r.json[0]['id']}/scans", json={"profile": "quick"}, headers={"Authorization": "Bearer s3cret"})
    assert r.status_code == 400 and "authorized" in r.json["error"]


def test_login_when_password_set(monkeypatch):
    monkeypatch.setenv("OPENASV_ADMIN_PASSWORD", "pw")
    c = _client()
    assert c.get("/").status_code == 302
    tok = re.search(r'name="csrf" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
    r = c.post("/login", data={"csrf": tok, "name": "Alex", "password": "pw"})
    assert r.status_code == 302 and c.get("/").status_code == 200


def test_vietnamese_interface_and_defaults(isolated):
    client = _client()
    r = client.get("/")
    assert 'lang="en"' in r.text and "Overview" in r.text
    r = client.get("/set/lang/vi", headers={"Referer": "http://localhost/scopes"})
    assert r.status_code == 302 and r.headers["Location"].endswith("/scopes")
    r = client.get("/")
    assert 'lang="vi"' in r.text and "Tổng quan" in r.text and ">Open<i>ASV</i>" in r.text
    assert client.get("/set/lang/xx").status_code == 404
    client.get("/set/theme/dark")
    assert 'data-theme="dark"' in client.get("/").text


def test_every_template_string_has_a_vietnamese_translation():
    import json
    from pathlib import Path

    from openasv import i18n
    root = Path(i18n.__file__).resolve().parent
    cat = json.loads((root / "vi.json").read_text(encoding="utf-8"))
    keys = set().union(*i18n.template_strings(root.parent / "web" / "templates").values())
    # product names, file formats and code samples stay as they are
    same = {"ASV", "CSV", "CVE", "CVSS", "CWE", "GitHub", "JSON", "Markdown", "Nmap", "Nuclei", "OWASP ZAP", "OpenASV",
            "PCI DSS", "PCI SSC ASV", "PDF", "Tenable Nessus", "Greenbone / OpenVAS", "testssl.sh", "· OpenASV"}
    missing = {k for k in keys - set(cat) - same if not k.startswith(("-", "config/", "http"))}
    assert not missing, f"add these to openasv/i18n/vi.json: {sorted(missing)}"


def test_translation_never_touches_attributes():
    from openasv import i18n
    out = i18n.wrap_source('<span class="chip {{ s.status }}" title="Hello there">{{ s.status }} done</span>')
    assert 'class="chip {{ s.status }}"' in out and "(s.status)|tr" in out and '_("Hello there")' in out
    i18n.set_lang("vi")
    try:
        assert i18n.translate("Overdue since {0}", "x") == "Quá hạn từ x"
        assert i18n.translate_value("3 special note(s) awaiting declaration") == "3 special note đang chờ khai báo"
    finally:
        i18n.set_lang("en")
