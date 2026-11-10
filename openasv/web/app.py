"""OpenASV web application (UI + REST API)."""
from __future__ import annotations

import json
import os
import re
import secrets
import tempfile
from datetime import datetime
from pathlib import Path

from flask import (Flask, Response, abort, flash, g, jsonify, redirect, render_template, request, send_from_directory,
                   session, url_for)
from werkzeug.utils import secure_filename

from .. import (DISCLAIMER, __version__, compliance, config, db, i18n, importers, report, scheduler, scoring,
                service, targets, worker)
from ..config import settings

EVIDENCE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".txt", ".log", ".json", ".xml", ".csv", ".conf", ".cfg", ".md"}


def _secret_key() -> str:
    if settings.secret_key:
        return settings.secret_key
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    p = settings.data_dir / ".secret_key"
    if not p.exists():
        p.write_text(secrets.token_hex(32))
        if os.name != "nt":
            os.chmod(p, 0o600)
    return p.read_text().strip()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(SECRET_KEY=_secret_key(), SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
                      MAX_CONTENT_LENGTH=64 * 1024 * 1024)
    app.jinja_env.add_extension(i18n.AutoTranslate)
    app.jinja_env.filters["tr"] = i18n.translate_value
    app.jinja_env.globals["_"] = i18n.translate
    db.init()
    worker.ensure_started()
    scheduler.start()

    # ------------------------------------------------------------- security plumbing
    @app.after_request
    def _headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'; base-uri 'none'; object-src 'none'")
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["X-Frame-Options"] = "DENY"
        return resp

    def csrf_token() -> str:
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(24)
        return session["csrf"]

    def actor() -> str:
        return g.get("api_actor") or session.get("user") or "operator"

    @app.before_request
    def _guard():
        g.api_actor = None
        g.lang = i18n.set_lang(request.args.get("lang") or request.cookies.get("lang"))
        g.theme = request.cookies.get("theme") if request.cookies.get("theme") in ("light", "dark") else "auto"
        p = request.path
        if p.startswith("/static/") or p in ("/healthz", "/login"):
            return None
        if p.startswith("/api/v1/"):
            tok = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
            if settings.api_token and tok and secrets.compare_digest(tok, settings.api_token):
                g.api_actor = "api"
                return None
            if session.get("user") and request.method == "GET":
                return None
            return jsonify(error="unauthorized", hint="Set OPENASV_API_TOKEN and send 'Authorization: Bearer <token>'"), 401
        if settings.admin_password and not session.get("authenticated"):
            return redirect(url_for("login", next=p))
        if request.method == "POST":
            tok = request.form.get("csrf") or request.headers.get("X-CSRF-Token")
            if not tok or not secrets.compare_digest(tok, session.get("csrf", "")):
                abort(400, "Invalid or missing CSRF token. Reload the page and try again.")
        return None

    @app.context_processor
    def _inject():
        return {"csrf_token": csrf_token, "version": __version__, "disclaimer": DISCLAIMER, "actor": actor(),
                "auth_enabled": bool(settings.admin_password), "lang": i18n.get_lang(),
                "theme": g.get("theme", "auto"), "languages": i18n.LANGUAGES, "STAGE_LABELS": worker.STAGE_LABELS,
                "special_note_defs": config.policy()["special_notes"], "dispute_kinds": scoring.DISPUTE_KINDS,
                "nav": request.endpoint or "", "cvss": __import__("openasv.cvss", fromlist=["base_score"]).base_score,
                "pending_disputes_count": lambda: db.one("SELECT COUNT(*) AS n FROM disputes WHERE status='pending'")["n"]}

    @app.template_filter("dt")
    def _dt(v, fmt="%d %b %Y %H:%M"):
        if not v:
            return "—"
        if i18n.get_lang() == "vi":
            fmt = fmt.replace("%d %b %Y", "%d/%m/%Y")
        if isinstance(v, str):
            try:
                v = datetime.fromisoformat(v)
            except ValueError:
                return v
        return v.strftime(fmt)

    @app.template_filter("d")
    def _d(v):
        return _dt(v, "%d %b %Y")

    def _err(e: Exception, to: str):
        flash(str(e), "error")
        return redirect(to)

    # ------------------------------------------------------------- auth
    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            if request.form.get("csrf") != session.get("csrf"):
                abort(400)
            name = (request.form.get("name") or "").strip()[:80]
            pw = request.form.get("password") or ""
            if settings.admin_password and secrets.compare_digest(pw, settings.admin_password) and name:
                session.clear()
                session.update(authenticated=True, user=name, csrf=secrets.token_urlsafe(24))
                db.audit(name, "auth.login", "session", request.remote_addr or "")
                nxt = request.args.get("next") or "/"
                return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")
            flash("Invalid name or password", "error")
        return render_template("login.html", printing=True)

    @app.post("/logout")
    def logout():
        session.clear()
        return redirect(url_for("dashboard"))

    @app.get("/set/<kind>/<value>")
    def set_pref(kind, value):
        """Interface language and colour theme are per-browser preferences kept in a cookie."""
        allowed = {"lang": tuple(i18n.LANGUAGES), "theme": ("light", "dark", "auto")}
        if value not in allowed.get(kind, ()):
            abort(404)
        back = request.referrer or ""
        back = "/" + back.split("://", 1)[-1].split("/", 1)[-1] if back.startswith(request.host_url) else url_for("dashboard")
        resp = redirect(back)
        resp.set_cookie(kind, value, max_age=365 * 86400, samesite="Lax", httponly=True)
        return resp

    @app.post("/operator")
    def set_operator():
        name = (request.form.get("name") or "").strip()[:80]
        if name and not settings.admin_password:
            session["user"] = name
        return redirect(request.referrer or url_for("dashboard"))

    # ------------------------------------------------------------- dashboard
    @app.get("/")
    def dashboard():
        rows = []
        for sc in db.scopes():
            st = compliance.scope_status(sc["id"])
            comps = db.components(sc["id"])
            rows.append({"scope": sc, "status": st, "in_scope": sum(c["status"] == "in_scope" for c in comps),
                         "discovered": sum(c["status"] == "discovered" for c in comps)})
        recent = db.q("SELECT s.*, sc.name AS scope_name FROM scans s JOIN scopes sc ON sc.id=s.scope_id "
                      "ORDER BY s.id DESC LIMIT 8")
        open_fail = 0
        sev = {"High": 0, "Medium": 0, "Low": 0}
        for r in rows:
            latest = r["status"]["latest"]
            if latest:
                ev = scoring.evaluate(latest)
                open_fail += ev["counts"]["fail"]
                for k in sev:
                    sev[k] += ev["counts"][k.lower()]
        pending = db.one("SELECT COUNT(*) AS n FROM disputes WHERE status='pending'")["n"]
        running = db.one("SELECT COUNT(*) AS n FROM scans WHERE status IN ('queued','running')")["n"]
        return render_template("dashboard.html", rows=rows, recent=recent, open_fail=open_fail, sev=sev,
                               pending=pending, running=running)

    # ------------------------------------------------------------- scopes
    @app.get("/scopes")
    def scopes():
        rows = [{"scope": s, "status": compliance.scope_status(s["id"]), "components": db.components(s["id"])}
                for s in db.scopes()]
        return render_template("scopes.html", rows=rows)

    @app.post("/scopes")
    def scope_create():
        f = request.form
        try:
            comps = [x for x in re.split(r"[\s,]+", f.get("components", "")) if x]
            sid = service.create_scope(f.get("name", ""), {"company": f.get("company", "")}, actor(), comps)
        except (service.ServiceError, targets.TargetError) as e:
            return _err(e, url_for("scopes"))
        flash("Scope created. Review the scan customer details and components.", "ok")
        return redirect(url_for("scope_page", sid=sid))

    @app.get("/scopes/<int:sid>")
    def scope_page(sid):
        sc = db.scope(sid) or abort(404)
        comps = db.components(sid)
        scans = db.q("SELECT * FROM scans WHERE scope_id=? ORDER BY id DESC", (sid,))
        return render_template("scope.html", sc=sc, comps=comps, scans=scans, st=compliance.scope_status(sid),
                               profiles=config.profiles(), schedules=service.SCHEDULES, tab=request.args.get("tab", "components"))

    @app.post("/scopes/<int:sid>/components")
    def components_add(sid):
        db.scope(sid) or abort(404)
        added, errors = 0, []
        for raw in re.split(r"[\s,]+", request.form.get("components", "")):
            if not raw:
                continue
            try:
                service.add_component(sid, raw, actor(), label=request.form.get("label", "")[:80])
                added += 1
            except targets.TargetError as e:
                errors.append(str(e))
        if added:
            flash(f"{added} component(s) added to scope.", "ok")
        for e in errors:
            flash(e, "error")
        return redirect(url_for("scope_page", sid=sid))

    @app.post("/scopes/<int:sid>/components/<int:cid>")
    def component_update(sid, cid):
        f = request.form
        try:
            if f.get("action") == "lb":
                service.set_component(sid, cid, actor(), load_balanced=f.get("load_balanced") == "1",
                                      lb_synchronized=f.get("lb_synchronized") == "1")
            else:
                service.set_component(sid, cid, actor(), status=f.get("status"), reason=f.get("reason", ""))
        except service.ServiceError as e:
            return _err(e, url_for("scope_page", sid=sid))
        return redirect(url_for("scope_page", sid=sid, tab=f.get("tab", "components")))

    @app.post("/scopes/<int:sid>/settings")
    def scope_settings(sid):
        f = request.form
        try:
            customer = {k: f.get(k, "") for k in ("company", "contact", "title", "phone", "email", "address", "city",
                                                  "state", "postal", "country", "website")}
            fields = {"name": f.get("name", ""), "customer": customer, "notes": f.get("notes", "")}
            if f.get("schedule"):
                if f["schedule"] != "none" and f.get("schedule_authorized") != "yes":
                    raise service.ServiceError("Confirm that recurring scans of this scope are authorized")
                fields.update(schedule=f["schedule"], schedule_profile=f.get("schedule_profile", "asv"))
            service.update_scope(sid, actor(), **fields)
        except service.ServiceError as e:
            return _err(e, url_for("scope_page", sid=sid, tab="settings"))
        flash("Scope settings saved.", "ok")
        return redirect(url_for("scope_page", sid=sid, tab="settings"))

    # ------------------------------------------------------------- scans
    @app.get("/scopes/<int:sid>/scan")
    def scan_new(sid):
        sc = db.scope(sid) or abort(404)
        comps = db.components(sid, "in_scope")
        checks = []
        for c in comps:
            try:
                reason = targets.authorize(targets.parse(c["value"]))
                checks.append((c, True, reason))
            except targets.TargetError as e:
                checks.append((c, False, str(e)))
        return render_template("scan_new.html", sc=sc, checks=checks, profiles=config.profiles(),
                               authorization=service.AUTHORIZATION_TEXT)

    @app.post("/scopes/<int:sid>/scans")
    def scan_launch(sid):
        f = request.form
        try:
            only = f.getlist("only") or None
            scan_id = service.launch_scan(sid, f.get("profile", "asv"), actor(), authorized=f.get("authorized") == "yes",
                                          label=f.get("label", ""), only=only)
        except service.ServiceError as e:
            return _err(e, url_for("scan_new", sid=sid))
        return redirect(url_for("scan_page", scan_id=scan_id))

    @app.get("/scans")
    def scans():
        rows = db.q("SELECT s.*, sc.name AS scope_name FROM scans s JOIN scopes sc ON sc.id=s.scope_id ORDER BY s.id DESC LIMIT 300")
        return render_template("scans.html", rows=rows)

    @app.get("/scans/<int:scan_id>")
    def scan_page(scan_id):
        s = db.scan(scan_id) or abort(404)
        ev = scoring.evaluate(s) if s["status"] == "completed" else None
        return render_template("scan.html", s=s, sc=db.scope(s["scope_id"]), ev=ev, upcoming=worker.upcoming(s))

    @app.get("/scans/<int:scan_id>/status.json")
    def scan_status(scan_id):
        s = db.scan(scan_id) or abort(404)
        lp = worker.log_path(scan_id)
        tail = lp.read_text(encoding="utf-8", errors="replace").splitlines()[-80:] if lp.exists() else []
        t = i18n.translate     # display strings follow the interface language; "status" stays machine-readable
        return jsonify(id=scan_id, status=s["status"], status_text=t(s["status"]), result=s["result"], error=s["error"],
                       log=tail, pending_text=t("pending"), waiting_text=t("Waiting for output…"),
                       stages=[{"ord": x["ord"], "name": x["name"], "label": t(worker.STAGE_LABELS.get(x["name"], x["name"])),
                                "target": x["target"], "status": x["status"], "status_text": t(x["status"]),
                                "progress": x["progress"], "message": x["message"]} for x in s["stages"]],
                       upcoming=[{**u, "label": t(u["label"])} for u in worker.upcoming(s)])

    @app.post("/scans/<int:scan_id>/cancel")
    def scan_cancel(scan_id):
        worker.cancel(scan_id)
        db.audit(actor(), "scan.cancel", f"scan:{scan_id}")
        return redirect(url_for("scan_page", scan_id=scan_id))

    @app.post("/scans/<int:scan_id>/rescan")
    def scan_rescan(scan_id):
        try:
            nid = service.rescan_failed(scan_id, actor(), request.form.get("authorized") == "yes")
        except service.ServiceError as e:
            return _err(e, url_for("scan_page", scan_id=scan_id))
        return redirect(url_for("scan_page", scan_id=nid))

    @app.get("/scans/<int:scan_id>/raw/<name>")
    def scan_raw(scan_id, name):
        name = secure_filename(name)
        if not name or name.startswith("."):
            abort(404)
        return send_from_directory(worker.run_dir(scan_id), name, mimetype="text/plain")

    # ------------------------------------------------------------- report & exports
    def _report(scan_id):
        r = report.build(scan_id) or abort(404)
        if r["scan"]["status"] != "completed":
            abort(409, "The scan has not completed yet")
        return r

    @app.get("/scans/<int:scan_id>/report")
    def report_page(scan_id):
        return render_template("report.html", r=_report(scan_id), printing=request.args.get("print") == "1")

    @app.get("/scans/<int:scan_id>/report.<fmt>")
    def report_export(scan_id, fmt):
        r = _report(scan_id)
        name = f"openasv-scan-{scan_id}"
        if fmt == "json":
            return Response(report.to_json(r), mimetype="application/json",
                            headers={"Content-Disposition": f"attachment; filename={name}.json"})
        if fmt == "csv":
            return Response(report.to_csv(r), mimetype="text/csv",
                            headers={"Content-Disposition": f"attachment; filename={name}-findings.csv"})
        if fmt == "md":
            return Response(report.to_markdown(r), mimetype="text/markdown",
                            headers={"Content-Disposition": f"attachment; filename={name}.md"})
        if fmt == "pdf":
            return _pdf(render_template("report.html", r=r, printing=True, pdf=True, inline_css=_css()), name)
        abort(404)

    def _css() -> str:
        return (Path(app.static_folder) / "app.css").read_text(encoding="utf-8")

    def _pdf(html: str, name: str):
        try:
            from weasyprint import HTML
        except Exception:  # noqa: BLE001
            abort(501, "PDF export requires WeasyPrint (included in the Docker image). Use Print → Save as PDF.")
        pdf = HTML(string=html, base_url=app.static_folder).write_pdf()
        return Response(pdf, mimetype="application/pdf", headers={"Content-Disposition": f"attachment; filename={name}.pdf"})

    # ------------------------------------------------------------- workbench: findings, notes, disputes
    @app.get("/scans/<int:scan_id>/findings")
    def findings_page(scan_id):
        r = _report(scan_id)
        ev = r["ev"]
        a = request.args
        items = ev["findings"]
        if a.get("status"):
            items = [f for f in items if f["status"] == a["status"]]
        if a.get("severity"):
            items = [f for f in items if f["severity"] == a["severity"] and f["status"] != "Info"]
        if a.get("component"):
            items = [f for f in items if f["component"] == a["component"]]
        if a.get("engine"):
            items = [f for f in items if f["engine"] == a["engine"]]
        if a.get("q"):
            ql = a["q"].lower()
            items = [f for f in items if ql in f"{f['title']} {f['category_title']} {' '.join(f['cve'])} {f['url']}".lower()]
        sel = next((f for f in ev["findings"] if f["key"] == a.get("f")), None)
        prev = db.q("SELECT id, finished_at, result FROM scans WHERE scope_id=? AND id<? AND status='completed' "
                    "ORDER BY id DESC LIMIT 5", (r["scan"]["scope_id"], scan_id))
        return render_template("findings.html", r=r, items=items, sel=sel, args=a, prev=prev,
                               engines=sorted({f["engine"] for f in ev["findings"]}),
                               comps=sorted({f["component"] for f in ev["findings"]}))

    def _save_evidence(scan_id: int) -> list[dict]:
        out = []
        d = worker.run_dir(scan_id) / "evidence"
        for fs in request.files.getlist("evidence"):
            if not fs or not fs.filename:
                continue
            name = secure_filename(fs.filename)
            ext = Path(name).suffix.lower()
            if ext not in EVIDENCE_EXT:
                raise service.ServiceError(f"Evidence type {ext} is not accepted")
            d.mkdir(parents=True, exist_ok=True)
            stored = f"{secrets.token_hex(4)}-{name}"
            fs.save(d / stored)
            out.append({"name": name, "stored": stored, "size": (d / stored).stat().st_size, "at": db.now()})
        return out

    @app.post("/scans/<int:scan_id>/disputes")
    def dispute_submit(scan_id):
        f = request.form
        back = url_for("findings_page", scan_id=scan_id, f=f.get("fkey")) if f.get("fkey") != scoring.SCAN_DISPUTE_KEY \
            else url_for("scan_page", scan_id=scan_id)
        try:
            ev = _save_evidence(scan_id)
            if f.get("evidence_text"):
                ev.append({"name": "Description of evidence", "text": f["evidence_text"][:4000], "at": db.now()})
            score = float(f["proposed_score"]) if f.get("proposed_score") else None
            keys = [f.get("fkey")]
            if f.get("apply_group") == "1":
                group = next((x["group_key"] for x in db.findings(scan_id) if x["key"] == f.get("fkey")), None)
                keys = [x["key"] for x in db.findings(scan_id) if group and x["group_key"] == group
                        and x["key"] not in db.disputes(scan_id)] or keys
            for k in keys:
                service.submit_dispute(scan_id, k, f.get("kind", ""), f.get("justification", ""), actor(),
                                       attested=f.get("attested") == "yes", evidence=ev, proposed_score=score)
        except (service.ServiceError, ValueError) as e:
            return _err(e, back)
        flash(f"Dispute submitted for review ({len(keys)} finding(s)).", "ok")
        return redirect(back)

    @app.post("/disputes/<int:did>/review")
    def dispute_review(did):
        db.one("SELECT * FROM disputes WHERE id=?", (did,)) or abort(404)
        try:
            service.review_dispute(did, request.form.get("decision", ""), request.form.get("reviewer", actor()),
                                   request.form.get("notes", ""))
        except service.ServiceError as e:
            flash(str(e), "error")
        return redirect(request.form.get("next") or url_for("disputes_page"))

    @app.post("/disputes/<int:did>/withdraw")
    def dispute_withdraw(did):
        d = db.one("SELECT * FROM disputes WHERE id=?", (did,)) or abort(404)
        try:
            service.withdraw_dispute(did, actor())
        except service.ServiceError as e:
            flash(str(e), "error")
        return redirect(url_for("findings_page", scan_id=d["scan_id"], f=d["fkey"]))

    @app.get("/disputes")
    def disputes_page():
        status = request.args.get("status", "pending")
        rows = db.q("SELECT d.*, s.scope_id, sc.name AS scope_name FROM disputes d JOIN scans s ON s.id=d.scan_id "
                    "JOIN scopes sc ON sc.id=s.scope_id WHERE (?='all' OR d.status=?) ORDER BY d.submitted_at DESC",
                    (status, status))
        fmap = {}
        for r in rows:
            r["evidence"] = json.loads(r["evidence"] or "[]")
            if r["scan_id"] not in fmap:
                fmap[r["scan_id"]] = {f["key"]: f for f in db.findings(r["scan_id"])}
            r["finding"] = fmap[r["scan_id"]].get(r["fkey"])
        return render_template("disputes.html", rows=rows, status=status)

    @app.get("/evidence/<int:scan_id>/<name>")
    def evidence(scan_id, name):
        return send_from_directory(worker.run_dir(scan_id) / "evidence", secure_filename(name), as_attachment=True)

    @app.post("/scans/<int:scan_id>/declarations")
    def declare(scan_id):
        f = request.form
        try:
            service.declare(scan_id, f.get("nkey", ""), f.get("option", ""), f.get("statement", ""), actor())
            flash("Declaration recorded.", "ok")
        except service.ServiceError as e:
            flash(str(e), "error")
        return redirect(url_for("findings_page", scan_id=scan_id, status="", _anchor="notes"))

    @app.post("/scans/<int:scan_id>/carry-forward")
    def carry(scan_id):
        try:
            n = service.carry_forward(scan_id, int(request.form.get("from_scan", 0)), actor())
            flash(f"{n} accepted dispute(s) re-submitted. They must be reviewed again for this scan period.", "ok")
        except (service.ServiceError, ValueError) as e:
            flash(str(e), "error")
        return redirect(url_for("findings_page", scan_id=scan_id))

    @app.route("/scans/<int:scan_id>/finalize", methods=["GET", "POST"])
    def finalize(scan_id):
        r = _report(scan_id)
        if request.method == "POST":
            f = request.form
            att = {"name": f.get("name", ""), "title": f.get("title", ""), "date": f.get("date", ""),
                   "scope_complete": f.get("scope_complete") == "yes", "evidence_accurate": f.get("evidence_accurate") == "yes",
                   "reviewer": f.get("reviewer", ""), "reviewer_notes": f.get("reviewer_notes", "")}
            try:
                service.finalize(scan_id, actor(), att)
            except service.ServiceError as e:
                return _err(e, url_for("finalize", scan_id=scan_id))
            flash("Report finalised. It can no longer be edited.", "ok")
            return redirect(url_for("report_page", scan_id=scan_id))
        return render_template("finalize.html", r=r, today=datetime.now().strftime("%Y-%m-%d"))

    # ------------------------------------------------------------- combined result
    @app.get("/scopes/<int:sid>/combine")
    def combine(sid):
        sc = db.scope(sid) or abort(404)
        scans_ = db.q("SELECT * FROM scans WHERE scope_id=? AND status='completed' ORDER BY id DESC", (sid,))
        ids = [int(x) for x in request.args.getlist("scan")]
        data, error = None, None
        if ids:
            try:
                data = report.build_combined(ids)
            except ValueError as e:
                error = str(e)
        if data and request.args.get("format") == "pdf":
            return _pdf(render_template("combined.html", sc=sc, scans=scans_, data=data, ids=ids, printing=True, pdf=True,
                                        inline_css=_css()), f"openasv-combined-{sid}")
        return render_template("combined.html", sc=sc, scans=scans_, data=data, ids=ids, error=error,
                               printing=request.args.get("print") == "1")

    # ------------------------------------------------------------- import
    @app.route("/import", methods=["GET", "POST"])
    def import_page():
        if request.method == "POST":
            fs = request.files.get("file")
            try:
                sid = int(request.form.get("scope_id") or 0)
                if not sid:
                    sid = service.create_scope(request.form.get("new_scope") or "Imported results", {}, actor())
                if not fs or not fs.filename:
                    raise service.ServiceError("Choose a file to import")
                with tempfile.TemporaryDirectory() as td:
                    p = Path(td) / secure_filename(fs.filename)
                    fs.save(p)
                    scan_id = importers.import_file(sid, p, actor(), fmt=request.form.get("format") or None)
            except (service.ServiceError, importers.ImportErrorX, ValueError) as e:
                return _err(e, url_for("import_page"))
            flash("Results imported and scored.", "ok")
            return redirect(url_for("report_page", scan_id=scan_id))
        return render_template("import.html", scopes=db.scopes(), formats=importers.FORMATS)

    # ------------------------------------------------------------- settings
    @app.get("/settings")
    def settings_page():
        from ..engines import eol
        return render_template(
            "settings.html", versions=worker.tool_versions(), policy=config.policy(), policy_hash=config.policy_hash(),
            target_policy=config.target_policy(), profiles=config.profiles(), eol_info=eol.data().get("generated"),
            s=settings, audit=db.q("SELECT * FROM audit ORDER BY id DESC LIMIT 60"))

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "version": __version__}

    # ------------------------------------------------------------- REST API v1
    @app.get("/api/v1/scopes")
    def api_scopes():
        return jsonify([{"id": s["id"], "name": s["name"], "schedule": s["schedule"],
                         "components": [{"value": c["value"], "status": c["status"]} for c in db.components(s["id"])],
                         "compliance": {k: str(v) if k in ("last_pass", "due") else v
                                        for k, v in compliance.scope_status(s["id"]).items() if k in ("state", "label", "last_pass", "due")}}
                        for s in db.scopes()])

    @app.post("/api/v1/scopes")
    def api_scope_create():
        b = request.get_json(force=True, silent=True) or {}
        try:
            sid = service.create_scope(b.get("name", ""), b.get("customer") or {}, actor(), b.get("components") or [])
        except (service.ServiceError, targets.TargetError) as e:
            return jsonify(error=str(e)), 400
        return jsonify(id=sid), 201

    @app.post("/api/v1/scopes/<int:sid>/scans")
    def api_scan(sid):
        b = request.get_json(force=True, silent=True) or {}
        try:
            scan_id = service.launch_scan(sid, b.get("profile", "asv"), actor(), authorized=b.get("authorized") is True,
                                          label=b.get("label", ""))
        except service.ServiceError as e:
            return jsonify(error=str(e)), 400
        return jsonify(id=scan_id, status_url=url_for("api_scan_get", scan_id=scan_id)), 202

    @app.get("/api/v1/scans/<int:scan_id>")
    def api_scan_get(scan_id):
        s = db.scan(scan_id) or abort(404)
        return jsonify(id=scan_id, status=s["status"], result=s["result"], error=s["error"],
                       report=url_for("report_export", scan_id=scan_id, fmt="json") if s["status"] == "completed" else None)

    @app.get("/api/v1/scans/<int:scan_id>/report")
    def api_report(scan_id):
        return Response(report.to_json(_report(scan_id)), mimetype="application/json")

    @app.post("/api/v1/import")
    def api_import():
        fs = request.files.get("file")
        try:
            sid = int(request.form.get("scope_id", 0))
            if not fs:
                raise service.ServiceError("file is required")
            with tempfile.TemporaryDirectory() as td:
                p = Path(td) / secure_filename(fs.filename or "upload")
                fs.save(p)
                scan_id = importers.import_file(sid, p, actor(), fmt=request.form.get("format") or None)
        except (service.ServiceError, importers.ImportErrorX, ValueError) as e:
            return jsonify(error=str(e)), 400
        return jsonify(id=scan_id, result=db.scan(scan_id)["result"]), 201

    @app.errorhandler(400)
    @app.errorhandler(404)
    @app.errorhandler(409)
    @app.errorhandler(501)
    def _http_err(e):
        if request.path.startswith("/api/"):
            return jsonify(error=e.description), e.code
        return render_template("error.html", code=e.code, message=e.description), e.code

    return app
