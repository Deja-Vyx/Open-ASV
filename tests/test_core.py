"""Core behaviour: CVSS, target policy, classification, engine parsers, scoring, workflow, importers."""
import json

import pytest

from openasv import compliance, config, cvss, db, findings, scoring, service, targets
from openasv.engines import eol, nmap, nuclei, nvd, testssl, web, zap
from conftest import make_ctx


# ----------------------------------------------------------------- CVSS 3.1
@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N", 3.1),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3),
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N", 7.4),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:L/A:N", 6.4),
])
def test_cvss_reference_scores(vector, score):
    assert cvss.base_score(vector) == score


def test_every_policy_vector_is_valid():
    from openasv import config
    for cat in config.policy()["categories"].values():
        if cat.get("vector"):
            cvss.base_score(cat["vector"])


# ----------------------------------------------------------------- target policy
def fake_resolve(h):
    return {"localhost": ["127.0.0.1"], "shop.example.com": ["203.0.113.10"], "intranet": ["10.1.2.3"]}.get(h, ["198.51.100.99"])


def test_target_policy_private_allowed_public_refused(isolated):
    assert "private" in targets.authorize(targets.parse("https://localhost:8443/"), fake_resolve)
    assert "private" in targets.authorize(targets.parse("intranet"), fake_resolve)
    with pytest.raises(targets.TargetError):
        targets.authorize(targets.parse("https://shop.example.com/"), fake_resolve)
    (isolated / "target-policy.yaml").write_text("allow_private_networks: false\nallow_hosts: ['*.example.com']\n")
    assert "allow_hosts" in targets.authorize(targets.parse("https://shop.example.com/"), fake_resolve)
    with pytest.raises(targets.TargetError):
        targets.authorize(targets.parse("localhost"), fake_resolve)


def test_target_policy_deny_and_cidr_limits(isolated):
    with pytest.raises(targets.TargetError):
        targets.authorize(targets.parse("169.254.169.254"), fake_resolve)
    with pytest.raises(targets.TargetError):
        targets.authorize(targets.parse("10.0.0.0/16"), fake_resolve)
    assert len(targets.expand(targets.parse("10.0.0.0/30"))) == 2


def test_component_parsing():
    c = targets.parse("HTTPS://Shop.Example.com:443/checkout?x=1")
    assert c.kind == "url" and c.url == "https://shop.example.com/checkout?x=1" and c.port == 443
    assert targets.parse("http://h:8080").url == "http://h:8080/"
    assert targets.parse("2001:db8::1").kind == "ip"
    for bad in ("ftp://x", "https://u:p@x/", "bad host", ""):
        with pytest.raises(targets.TargetError):
            targets.parse(bad)
    assert targets.registrable_domain("pay.shop.example.co.uk") == "example.co.uk"
    assert targets.registrable_domain("api.shop.vn") == "shop.vn"
    assert targets.registrable_domain("app.local") is None
    assert targets.registrable_domain("10.0.0.0/30") is None and targets.registrable_domain("203.0.113.5") is None


# ----------------------------------------------------------------- classification
def test_classification_precedence():
    assert findings.classify(rule_map={"40018": "sql_injection"}, rule_id="40018", title="x") == "sql_injection"
    assert findings.classify(cwe=["CWE-79"], title="whatever") == "xss"
    assert findings.classify(title="TLS Version 1.0 Protocol Detection") == "ssl_early_tls"
    assert findings.classify(title="Unsupported Web Server Detection") == "unsupported_software"
    assert findings.classify(title="DNS Server Zone Transfer Information Disclosure (AXFR)") == "dns_zone_transfer"
    assert findings.classify(title="Nothing special", default="other_network") == "other_network"


# ----------------------------------------------------------------- engine parsers on real output layouts
def test_nmap_parser_services_and_special_notes(fix):
    ctx = make_ctx(host="lab")
    nmap.parse(fix / "nmap_sample.xml", ctx)
    cats = {f["category"] for f in ctx.findings}
    assert {"open_port", "database_exposed"} <= cats
    types = {n["type"] for n in ctx.notes}
    assert {"insecure_service"} <= types  # ftp
    web443 = next(s for s in ctx.state["services"] if s["port"] == 443)
    assert web443["tls"] and web443["web"]
    assert any(b["product"] == "nginx" and b["version"] == "1.27.0" for b in ctx.state["banners"])


def test_testssl_parser(fix):
    ctx = make_ctx(host="lab")
    testssl.parse(fix / "testssl_sample.json", ctx, 443)
    by = {f["rule_id"]: f for f in ctx.findings}
    assert by["TLS1"]["category"] == "ssl_early_tls" and by["TLS1"]["auto_fail"]
    assert by["TLS1_1"]["category"] == "deprecated_tls"
    assert "SSLv3" not in by                                   # "not offered" never matches
    assert by["cert_chain_of_trust"]["category"] == "cert_untrusted"
    assert by["cert_expirationStatus"]["category"] == "cert_expired"
    assert by["SWEET32"]["category"] == "weak_cipher"
    assert by["secure_client_renego"]["dos_exempt"]
    assert "heartbleed" not in by and "BEAST" not in by


def test_testssl_fatal_is_engine_error(tmp_path):
    from openasv.engines.base import EngineError
    p = tmp_path / "t.json"
    p.write_text(json.dumps([{"id": "engine_problem", "severity": "WARN", "finding": "x"},
                             {"id": "scanProblem", "severity": "FATAL", "finding": "couldn't connect"},
                             {"id": "scanTime", "severity": "WARN", "finding": "Scan interrupted"}]))
    with pytest.raises(EngineError):
        testssl.parse(p, make_ctx(), 443)


def test_zap_parser(fix):
    alerts = json.loads((fix / "zap_alerts_sample.json").read_text())["alerts"]
    ctx = make_ctx(host="localhost", tool_host="host.docker.internal")
    zap.parse(alerts, ctx)
    fs = findings.consolidate(ctx.findings)
    xss = [f for f in fs if f["category"] == "xss"]
    assert len(xss) == 2, "failing web findings stay one per URL/parameter"
    assert all(f["url"].startswith("https://localhost:8443") for f in xss)
    csp = [f for f in fs if f["category"] == "missing_security_header"]
    assert len(csp) == 1 and csp[0]["cvss_score"] < 4.0
    assert not any(f["rule_id"] == "zap-10027" for f in fs)   # informational dropped
    js = next(f for f in fs if f["rule_id"] == "zap-10003")
    assert js["cve"] == ["CVE-2020-11022", "CVE-2020-11023"]


def test_nuclei_parser(fix):
    ctx = make_ctx(host="localhost", tool_host="host.docker.internal")
    nuclei.parse(fix / "nuclei_sample.jsonl", ctx)
    by = {f["extra"]["template"]: f for f in ctx.findings}
    assert by["CVE-2021-41773"]["cvss_source"] == "nvd" and by["CVE-2021-41773"]["cvss_score"] == 7.5
    assert by["CVE-2021-41773"]["category"] == "path_traversal"
    assert by["tomcat-default-login"]["category"] == "default_account"
    assert by["lab-pan-in-response"]["evidence"] == "411111******1111"
    assert "lab-pan-invalid" not in by


def test_web_banner_parsing():
    assert web.parse_banners("Apache/2.4.29 (Ubuntu) OpenSSL/1.1.1") == [("Apache", "2.4.29"), ("OpenSSL", "1.1.1")]
    assert web.parse_banners("Werkzeug/2.0.1 Python/3.8.10") == [("Werkzeug", "2.0.1"), ("Python", "3.8.10")]


def test_eol_detection():
    r = eol.evaluate_banner("Python", "3.8.10")
    assert r["key"] == "python" and r["cycle"] == "3.8" and r["eol"]
    assert eol.evaluate_banner("PHP", "7.2.24")["eol"]
    assert eol.evaluate_banner("Microsoft-IIS", "8.5")["key"] == "windows-server"
    assert eol.evaluate_banner("nginx", "1.18.0")["eol"]
    assert eol.evaluate_banner("jquery", "1.12.4")["eol"]
    assert eol.evaluate_banner("Unknown thing", "1.0") is None
    assert eol.evaluate_banner("Apache", "2.4.62")["eol"] is False
    assert eol.product_key("", ["cpe:/a:apache:http_server:2.4.29"]) == "apache-http-server"


def test_nvd_mapping(fix):
    ctx = make_ctx()
    banner = {"product": "nginx", "version": "1.18.0", "cpe": [], "port": 443, "source": "http header server"}
    cpe = nvd.cpe_for(banner)
    assert cpe == "cpe:2.3:a:f5:nginx:1.18.0"
    assert nvd.cpe_for({"product": "MySQL", "version": "5.5.62-log", "cpe": []}) == "cpe:2.3:a:oracle:mysql:5.5.62"
    n = nvd.to_findings(ctx, banner, cpe, json.loads((fix / "nvd_nginx.json").read_text()))
    assert n == 2
    by = {f["cve"][0]: f for f in ctx.findings}
    assert by["CVE-2021-23017"]["cvss_score"] == 8.1 and by["CVE-2021-23017"]["potential"]
    assert by["CVE-2019-9511"]["category"] == "dos_only"


# ----------------------------------------------------------------- scoring & workflow
def _scan_with(fs, notes=None, comps=("shop.example.com",), meta=None):
    sid = service.create_scope("Shop", {"company": "Example"}, "tester")
    scan_id = db.x("INSERT INTO scans (scope_id,created_at,started_at,finished_at,status,profile,components,authorized_by,"
                   "authorization,meta) VALUES (?,?,?,?,?,?,?,?,?,?)",
                   (sid, db.now(), db.now(), db.now(), "completed", "asv",
                    json.dumps([{"value": c, "kind": "host", "host": c} for c in comps]), "tester", "ok",
                    json.dumps(meta or {})))
    db.save_findings(scan_id, findings.consolidate(fs))
    db.save_notes(scan_id, notes or [])
    return sid, scan_id


def mk(cat, comp="shop.example.com", **kw):
    return findings.make("test", cat, comp, kw.pop("title", cat), **kw)


def test_scoring_rules_and_components():
    _, scan_id = _scan_with([mk("missing_security_header"), mk("xss", url="https://shop.example.com/?q=1", param="q"),
                             mk("dos_only"), mk("open_port", port=443), mk("known_cve", cvss_score=5.0)])
    ev = scoring.evaluate(db.scan(scan_id))
    st = {f["category"]: f["status"] for f in ev["findings"]}
    assert st == {"missing_security_header": "Pass", "xss": "Fail", "dos_only": "Pass", "open_port": "Info", "known_cve": "Fail"}
    assert ev["overall"] == "FAIL" and ev["counts"]["fail"] == 2 and ev["counts"]["auto_fail"] == 1
    assert ev["components"][0]["status"] == "FAIL"


def test_special_notes_block_pass_until_declared():
    note = {"key": "n1", "type": "remote_access", "component": "shop.example.com", "port": 22, "detail": "ssh", "source": "nmap"}
    _, scan_id = _scan_with([mk("open_port", port=22)], [note])
    assert scoring.evaluate(db.scan(scan_id))["overall"] == "FAIL"
    with pytest.raises(service.ServiceError):
        service.declare(scan_id, "n1", "justified", "too short", "tester")
    service.declare(scan_id, "n1", "justified", "Admin SSH restricted to VPN source range with MFA.", "tester")
    assert scoring.evaluate(db.scan(scan_id))["overall"] == "PASS"


def test_load_balancer_note_is_derived():
    sid = service.create_scope("LB", {}, "t")
    scan_id = db.x("INSERT INTO scans (scope_id,created_at,finished_at,status,profile,components,authorized_by,authorization) "
                   "VALUES (?,?,?,?,?,?,?,?)", (sid, db.now(), db.now(), "completed", "asv",
                                                json.dumps([{"value": "lb.local", "host": "lb.local", "load_balanced": True}]),
                                                "t", "ok"))
    ev = scoring.evaluate(db.scan(scan_id))
    assert ev["overall"] == "FAIL" and ev["pending_notes"][0]["type"] == "load_balancer"


def test_dispute_lifecycle():
    _, scan_id = _scan_with([mk("sql_injection", url="https://shop.example.com/s?q=1", param="q")])
    f = db.findings(scan_id)[0]
    with pytest.raises(service.ServiceError):
        service.submit_dispute(scan_id, f["key"], "false_positive", "x" * 40, "cust", attested=False)
    did = service.submit_dispute(scan_id, f["key"], "false_positive",
                                 "Parameter is cast to integer server-side; see attached code excerpt.", "cust", attested=True)
    ev = scoring.evaluate(db.scan(scan_id))
    assert ev["overall"] == "FAIL" and ev["pending_disputes"]
    with pytest.raises(service.ServiceError):
        service.finalize(scan_id, "x", {"name": "a", "title": "b", "date": "c", "scope_complete": True,
                                        "evidence_accurate": True, "reviewer": "r"})
    service.review_dispute(did, "accepted", "Reviewer One", "Verified by replaying the payload manually.")
    ev = scoring.evaluate(db.scan(scan_id))
    assert ev["overall"] == "PASS" and ev["findings"][0]["exception_label"] == "False positive"
    service.finalize(scan_id, "x", {"name": "a", "title": "b", "date": "c", "scope_complete": True,
                                    "evidence_accurate": True, "reviewer": "r"})
    with pytest.raises(service.ServiceError):
        service.submit_dispute(scan_id, f["key"], "exception", "y" * 40, "cust", attested=True)


def test_cvss_dispute_rescores():
    _, scan_id = _scan_with([mk("known_cve", cvss_score=5.3)])
    f = db.findings(scan_id)[0]
    did = service.submit_dispute(scan_id, f["key"], "cvss", "Vulnerable module is not loaded; environmental score lower.",
                                 "c", attested=True, proposed_score=3.1)
    service.review_dispute(did, "accepted", "R", "Confirmed module disabled in config.")
    ev = scoring.evaluate(db.scan(scan_id))
    assert ev["findings"][0]["cvss_score"] == 3.1 and ev["findings"][0]["status"] == "Pass"


def test_inconclusive_scan_fails_until_dispute_accepted():
    _, scan_id = _scan_with([], meta={"inconclusive": ["Target stopped answering"]})
    assert scoring.evaluate(db.scan(scan_id))["overall"] == "FAIL"
    did = service.submit_dispute(scan_id, scoring.SCAN_DISPUTE_KEY, "inconclusive",
                                 "Firewall logs show no blocks during the window.", "c", attested=True)
    service.review_dispute(did, "accepted", "R", "Logs reviewed for the full scan window.")
    assert scoring.evaluate(db.scan(scan_id))["overall"] == "PASS"


def test_discovered_components_must_be_resolved():
    sid, scan_id = _scan_with([], meta={"discovered": [{"value": "mail.example.com", "kind": "host",
                                                         "reason": "MX record", "status": "discovered"}]})
    db.upsert_component(sid, "host", "mail.example.com", status="discovered", source="discovered")
    assert scoring.evaluate(db.scan(scan_id))["overall"] == "FAIL"
    cid = db.one("SELECT id FROM components WHERE value='mail.example.com'")["id"]
    with pytest.raises(service.ServiceError):
        service.set_component(sid, cid, "t", status="out_of_scope", reason="no")
    service.set_component(sid, cid, "t", status="out_of_scope", reason="Hosted mail provider, no CDE connectivity")
    assert scoring.evaluate(db.scan(scan_id))["overall"] == "PASS"


def test_combine_failing_scan_with_rescan():
    sid, a = _scan_with([mk("xss", url="https://shop.example.com/?q=1", param="q"), mk("open_port", port=443)])
    b = db.x("INSERT INTO scans (scope_id,created_at,finished_at,status,profile,report_type,components,authorized_by,authorization) "
             "VALUES (?,?,?,?,?,?,?,?,?)", (sid, db.now(), db.now(), "completed", "asv", "rescan",
                                            json.dumps([{"value": "shop.example.com", "host": "shop.example.com"}]), "t", "ok"))
    db.save_findings(b, findings.consolidate([mk("open_port", port=443)]))
    c = compliance.combine([a, b])
    assert c["overall"] == "PASS" and len(c["remediated"]) == 1 and c["remediated"][0]["validated_by"] == b


def test_combine_counts_zone_transfer_retest_on_name_server():
    axfr = findings.make("dns", "dns_zone_transfer", "ns1.example.com", "Zone transfer (AXFR) of example.com allowed",
                         port=53, rule_id="axfr-example.com")
    sid, a = _scan_with([axfr])
    assert compliance.combine([a])["overall"] == "FAIL"
    b = db.x("INSERT INTO scans (scope_id,created_at,finished_at,status,profile,report_type,components,authorized_by,authorization,meta) "
             "VALUES (?,?,?,?,?,?,?,?,?,?)", (sid, db.now(), db.now(), "completed", "asv", "rescan",
                                              json.dumps([{"value": "shop.example.com", "host": "shop.example.com"}]), "t", "ok",
                                              json.dumps({"dns_checked": ["ns1.example.com"]})))
    c = compliance.combine([a, b])
    assert not c["failing"] and [f["category"] for f in c["remediated"]] == ["dns_zone_transfer"]


def test_cross_engine_certificate_merge():
    a = mk("cert_untrusted", port=443, title="cert_chain_of_trust: failed (self signed).", evidence="testssl")
    b = findings.make("nuclei", "cert_untrusted", "shop.example.com", "Self Signed SSL Certificate", port=443, evidence="nuclei")
    out = findings.consolidate([a, b])
    assert len(out) == 1 and "nuclei" in out[0]["engine"] and "nuclei" in out[0]["evidence"]
    assert findings.classify(title="Expired SSL Certificate") == "cert_expired"


def test_testssl_is_authoritative_for_tls():
    from openasv.worker import prefer_testssl
    n = findings.make("nuclei", "cert_untrusted", "h", "Untrusted Root Certificate - Detect", port=443, extra={"tags": ["ssl"]})
    t = findings.make("testssl", "weak_cipher", "h", "x", port=443)
    other = findings.make("nuclei", "cert_untrusted", "h", "Untrusted", port=8443, extra={"tags": ["ssl"]})
    assert prefer_testssl([n, t, other], {443}) == [t, other]


def test_embedded_content_notes_deduplicated():
    ctx = make_ctx()
    alerts = [{"pluginId": "10017", "alert": "Cross-Domain JavaScript Source File Inclusion", "risk": "Low",
               "url": f"https://shop.example.com/p{i}", "evidence": '<script src="https://cdn.other.net/a.js"></script>'}
              for i in range(5)]
    zap.parse(alerts, ctx)
    assert len(ctx.notes) == 1 and "cdn.other.net" in ctx.notes[0]["detail"] and not ctx.findings


def test_pan_never_stored():
    f = mk("pan_in_response", evidence="card 4111 1111 1111 1111 on page", title="PAN 4111111111111111")
    assert "4111111111111111" not in json.dumps(f) and "411111******1111" in f["evidence"]


# ----------------------------------------------------------------- importers
def test_import_nessus(fix):
    from openasv import importers
    sid = service.create_scope("Imported", {}, "t")
    scan_id = importers.import_file(sid, fix / "sample.nessus", "t")
    ev = scoring.evaluate(db.scan(scan_id))
    cats = {f["category"] for f in ev["findings"]}
    assert {"ssl_early_tls", "database_exposed", "open_port", "xss"} <= cats
    tls = next(f for f in ev["findings"] if f["category"] == "ssl_early_tls")
    assert tls["auto_fail"] and tls["cvss_source"] == "imported" and tls["cvss_score"] == 6.5
    php = next(f for f in ev["findings"] if "PHP" in f["title"])
    assert php["cvss_score"] == 7.5 and "CVE-2020-7070" in php["cve"]
    assert any(n["type"] == "remote_access" for n in ev["notes"])
    assert ev["components"][0]["component"] == "shop.example.com" and ev["overall"] == "FAIL"


def test_import_gvm(fix):
    from openasv import importers
    sid = service.create_scope("GVM", {}, "t")
    scan_id = importers.import_file(sid, fix / "sample-gvm.xml", "t")
    fs = db.findings(scan_id)
    by = {f["title"]: f for f in fs}
    assert by["Anonymous FTP Login Reporting"]["category"] == "default_account"
    assert by["Missing `httpOnly` Cookie Attribute (HTTP)"]["category"] == "cookie_flags"
    assert by["Missing `httpOnly` Cookie Attribute (HTTP)"]["cvss_score"] == 5.0
    assert "OS Detection Consolidation and Reporting" not in by


def test_format_detection(fix):
    from openasv import importers
    assert importers.detect(fix / "sample.nessus") == "nessus"
    assert importers.detect(fix / "sample-gvm.xml") == "gvm"
    assert importers.detect(fix / "nmap_sample.xml") == "nmap"
    assert importers.detect(fix / "testssl_sample.json") == "testssl"
    assert importers.detect(fix / "nuclei_sample.jsonl") == "nuclei"


def test_upcoming_stages_follow_profile_pipeline():
    from openasv import worker
    s = {"status": "running", "profile": "asv", "stages": [{"name": "preflight"}, {"name": "nmap"}]}
    names = [x["name"] for x in worker.upcoming(s)]
    assert names[0] == "testssl" and names[-1] == "scoring" and "nmap" not in names
    assert worker.upcoming({**s, "status": "completed"}) == []


def test_recover_marks_interrupted_scans(monkeypatch):
    from openasv import worker
    sid, a = _scan_with([])
    db.update_scan(a, status="running")
    q = db.x("INSERT INTO scans (scope_id,created_at,status,profile,components,authorized_by,authorization) "
             "VALUES (?,?,?,?,?,?,?)", (sid, db.now(), "queued", "asv", "[]", "t", "ok"))
    seen = []
    monkeypatch.setattr(worker, "enqueue", seen.append)
    assert worker.recover() == [q] and seen == [q]
    assert db.scan(a)["status"] == "failed" and "Interrupted" in db.scan(a)["error"]


def test_second_process_does_not_fail_running_scans():
    sid, a = _scan_with([])
    db.update_scan(a, status="running")
    db.init()          # e.g. `openasv report` started while the server is scanning
    assert db.scan(a)["status"] == "running"


# ---------------------------------------------------------------- black-box extensions
def test_ssh_audit_separates_broken_from_weak():
    from openasv.engines import sshaudit
    ctx = make_ctx()
    sshaudit.parse({
        "banner": {"protocol": "2.0", "raw": "SSH-2.0-OpenSSH_7.4"},
        "kex": [{"algorithm": "curve25519-sha256"}, {"algorithm": "ecdh-sha2-nistp256", "notes": {"fail": ["suspected back-door"]}}],
        "key": [{"algorithm": "rsa-sha2-512", "keysize": 1024, "notes": {"fail": ["small key"]}}],
        "enc": [{"algorithm": "aes128-ctr"}, {"algorithm": "3des-cbc", "notes": {"fail": ["broken"]}}],
        "mac": [{"algorithm": "hmac-md5", "notes": {"fail": ["broken"]}}, {"algorithm": "hmac-sha1", "notes": {"warn": ["weak"]}}],
    }, ctx, 22)
    by = {f["category"]: f for f in ctx.findings}
    assert set(by) == {"ssh_broken_crypto", "ssh_weak_crypto", "crypto_inventory"}
    assert "3des-cbc" in by["ssh_broken_crypto"]["evidence"] and "1024-bit" in by["ssh_broken_crypto"]["evidence"]
    assert "nistp256" in by["ssh_weak_crypto"]["evidence"] and "nistp256" not in by["ssh_broken_crypto"]["evidence"]


def test_new_categories_score_as_intended():
    sid, a = _scan_with([
        findings.make("ssh-audit", "ssh_broken_crypto", "shop.example.com", "broken", port=22),
        findings.make("ssh-audit", "ssh_weak_crypto", "shop.example.com", "weak", port=22),
        findings.make("dns", "email_spoofing", "shop.example.com", "no dmarc"),
        findings.make("pages", "script_no_integrity_payment", "shop.example.com", "no sri", port=443),
        findings.make("pages", "script_inventory", "shop.example.com", "inventory", port=443),
        findings.make("wafw00f", "waf_presence", "shop.example.com", "No web application firewall detected", port=443),
    ])
    ev = scoring.evaluate(db.scan(a))
    status = {f["category"]: f["status"] for f in ev["findings"]}
    assert status == {"ssh_broken_crypto": "Fail", "ssh_weak_crypto": "Pass", "email_spoofing": "Pass",
                      "script_no_integrity_payment": "Pass", "script_inventory": "Info", "waf_presence": "Info"}
    assert {f["category"] for f in ev["evidence"]} == {"script_inventory", "waf_presence"} and not ev["services"]


def test_waf_detection_result():
    from openasv.engines import waf
    ctx = make_ctx()
    waf.parse([{"detected": True, "firewall": "Cloudflare", "manufacturer": "Cloudflare Inc."}], ctx, "https://shop.example.com/")
    waf.parse([{"detected": False, "firewall": "None", "manufacturer": "None"}], ctx, "https://shop.example.com:8443/")
    assert [f["title"] for f in ctx.findings] == ["Web application firewall detected", "No web application firewall detected"]
    assert ctx.findings[1]["potential"] and ctx.state["waf"]["https://shop.example.com/"] == ["Cloudflare (Cloudflare Inc.)"]


def test_page_inventory_findings():
    from openasv.engines import pages
    ctx = make_ctx()
    inv = {"https://shop.example.com/checkout": {
        "scripts": {"https://cdn.other.net/tag.js": {"external": True, "integrity": False, "sha256": ""},
                    "https://shop.example.com/app.js": {"external": False, "integrity": False, "sha256": "aa"}},
        "inline": ["x1"], "headers": {}, "payment": True, "login": True}}
    pages.report(ctx, inv)
    cats = [f["category"] for f in ctx.findings]
    assert cats == ["script_inventory", "script_no_integrity_payment", "auth_interface"]
    assert "cdn.other.net" in ctx.findings[1]["evidence"] and "app.js" not in ctx.findings[1]["evidence"]


def test_change_detection_only_compares_what_both_scans_tested():
    from openasv import changes
    old = {"services": {"a": ["443/tcp https"], "b": ["22/tcp ssh"]},
           "pages": {"https://a/": {"scripts": {"https://a/x.js": {"sha256": "1", "integrity": False}}, "inline": ["i1"],
                                    "headers": {"content-security-policy": "default-src 'self'"}}}}
    new = {"services": {"a": ["443/tcp https-alt (nginx)", "3306/tcp mysql"]},     # a relabelled service is not a change
           "pages": {"https://a/": {"scripts": {"https://a/x.js": {"sha256": "2", "integrity": False},
                                                "https://evil.test/s.js": {"sha256": "", "integrity": False}},
                                    "inline": ["i1"], "headers": {}, "payment": True},
                     "https://a/new": {"scripts": {}, "inline": [], "headers": {}}}}
    d = changes.compare(old, new)
    assert d["services"] == [{"host": "a", "added": ["3306/tcp mysql"], "removed": []}]
    pg = d["pages"][0]
    assert len(d["pages"]) == 1 and pg["scripts_added"] == ["https://evil.test/s.js"]
    assert pg["scripts_changed"] == ["https://a/x.js"] and pg["headers_changed"] == ["content-security-policy"]
    fs = changes.to_findings(d, 7)
    assert [f["category"] for f in fs] == ["service_change", "page_change"] and fs[1]["title"].startswith("Payment page")
    assert changes.compare(new, new) == {"services": [], "pages": []}


def test_email_authentication_checks(monkeypatch):
    from openasv.engines import dns as dns_engine
    records = {"example.com": ["v=spf1 include:_spf.example.net ~all"], "_dmarc.example.com": ["v=DMARC1; p=none"]}
    monkeypatch.setattr(dns_engine, "_txt", lambda r, name: records.get(name, []))
    ctx = make_ctx()
    dns_engine.email_authentication(ctx, None, "example.com", {"shop.example.com"})
    assert len(ctx.findings) == 1 and "DMARC policy" in ctx.findings[0]["evidence"] and "SPF" not in ctx.findings[0]["evidence"]
    assert ctx.findings[0]["component"] == "shop.example.com"
    records["_dmarc.example.com"] = ["v=DMARC1; p=reject"]
    ctx2 = make_ctx()
    dns_engine.email_authentication(ctx2, None, "example.com", set())
    assert not ctx2.findings


def test_pipeline_includes_black_box_extensions():
    from openasv import worker
    names = worker.host_pipeline(config.profiles()["asv"])
    assert names.index("testssl") < names.index("ssh") < names.index("web") < names.index("waf") < names.index("zap") \
        < names.index("pages") < names.index("nuclei")
    assert all(n in worker.STAGE_LABELS for n in names)
