"""Deliberately vulnerable demo target for trying OpenASV safely on your own machine.

    DEMO_MODE=weak    TLS 1.0/1.1 + weak ciphers + expired self-signed certificate, SQL injection, reflected XSS,
                      login form over plain HTTP, directory listing, script from an external domain, PAN on a
                      receipt page, exposed MySQL and SSH services, end-of-life version banners.
    DEMO_MODE=strong  The same application with every issue fixed (TLS 1.2+, CA-signed certificate, parameterised
                      queries, auto-escaping, security headers, no extra services).

Never expose this service to a network you do not control.
"""
from __future__ import annotations

import datetime as dt
import html
import os
import socket
import sqlite3
import ssl
import struct
import threading
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from flask import Flask, make_response, render_template_string, request
from werkzeug.serving import WSGIRequestHandler, make_server

MODE = os.environ.get("DEMO_MODE", "weak").lower()
WEAK = MODE != "strong"
HOST = os.environ.get("DEMO_HOSTNAME", "demo-target")
BIND = os.environ.get("DEMO_BIND", "0.0.0.0")
HTTPS_PORT = int(os.environ.get("DEMO_HTTPS_PORT", "8443"))
HTTP_PORT = int(os.environ.get("DEMO_HTTP_PORT", "8080"))
MYSQL_PORT = int(os.environ.get("DEMO_MYSQL_PORT", "3306"))
SSH_PORT = int(os.environ.get("DEMO_SSH_PORT", "2222"))
CA_DIR = Path(os.environ.get("DEMO_CA_DIR", "/demo-ca"))
CERT_DIR = Path(os.environ.get("DEMO_CERT_DIR", "/tmp/demo-certs"))

app = Flask(__name__)
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.executescript("""
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER);
INSERT INTO products (name, price) VALUES ('Canvas tote', 24), ('Steel bottle', 31), ('Notebook', 9);
""")

PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Demo storefront</title>
{% if weak %}<meta name="generator" content="WordPress 5.8.3">
<script src="https://cdn.example-analytics.net/tag.js"></script><script src="/static/jquery-1.12.4.min.js"></script>{% endif %}
</head><body><h1>Demo storefront</h1>
<form action="/search"><input name="q" value="{{ q }}"><button>Search</button></form>
<ul>{% for p in products %}<li><a href="/product?id={{ p[0] }}">{{ p[1] }}</a> ${{ p[2] }}</li>{% endfor %}</ul>
<p><a href="/search?q=bottle">Bottles</a> | <a href="/receipt">Last receipt</a> | <a href="/login">Sign in</a>{% if weak %} | <a href="/files/">Files</a>{% endif %}</p>
{{ extra|safe }}</body></html>"""


@app.after_request
def headers(resp):
    if not WEAK:
        resp.headers["Content-Security-Policy"] = "default-src 'self'; frame-ancestors 'none'"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    else:
        resp.headers["X-Powered-By"] = "PHP/7.2.24"
    return resp


def page(q="", rows=None, extra=""):
    return render_template_string(PAGE, weak=WEAK, q=q, products=rows if rows is not None else
                                  DB.execute("SELECT id,name,price FROM products").fetchall(), extra=extra)


@app.get("/")
def index():
    resp = make_response(page())
    resp.set_cookie("sid", "demo", secure=not WEAK, httponly=not WEAK, samesite=None if WEAK else "Strict")
    return resp


@app.get("/search")
def search():
    q = request.args.get("q", "")
    if not WEAK:
        rows = DB.execute("SELECT id,name,price FROM products WHERE name LIKE ?", (f"%{q}%",)).fetchall()
        return page(q, rows)
    try:  # vulnerable: string-built SQL and unescaped reflection
        rows = DB.execute(f"SELECT id,name,price FROM products WHERE name LIKE '%{q}%'").fetchall()
        err = ""
    except sqlite3.Error as e:
        rows, err = [], f"<pre>sqlite3.OperationalError: {html.escape(str(e))}</pre>"
    return page("", rows, f"<p>Results for: {q}</p>{err}")


@app.get("/product")
def product():
    pid = request.args.get("id", "1")
    if not WEAK:
        row = DB.execute("SELECT id,name,price FROM products WHERE id=?", (pid,)).fetchone()
    else:
        try:
            row = DB.execute(f"SELECT id,name,price FROM products WHERE id={pid}").fetchone()
        except sqlite3.Error as e:
            return f"<pre>sqlite3.OperationalError: {html.escape(str(e))}</pre>", 500
    return page("", [row] if row else [])


@app.get("/receipt")
def receipt():
    pan = "4111111111111111"  # public test PAN published by card brands, not a real card
    shown = pan if WEAK else pan[:6] + "******" + pan[-4:]
    return page("", [], f"<p>Receipt R-1001: card {shown}</p>")


@app.get("/login")
def login():
    return page("", [], '<form method="post" action="/login"><input name="user"><input type="password" name="pw"><button>Sign in</button></form>')


@app.get("/files/")
def files():
    if not WEAK:
        return "Not found", 404
    return ("<html><head><title>Index of /files/</title></head><body><h1>Index of /files/</h1><pre>"
            '<a href="../">../</a>\n<a href="backup.zip">backup.zip</a>  2026-01-10 10:00  4M\n</pre></body></html>')


@app.get("/static/jquery-1.12.4.min.js")
def jquery():
    return "/*! jQuery v1.12.4 | (c) jQuery Foundation | jquery.org/license */", 200, {"Content-Type": "application/javascript"}


# ------------------------------------------------------------------ extra services (weak mode)
def mysql_greeting() -> bytes:
    body = (b"\x0a" + b"5.5.62-log\x00" + struct.pack("<I", 8) + b"abcdefgh\x00" + struct.pack("<H", 0xF7FF)
            + b"\x21" + struct.pack("<H", 2) + struct.pack("<H", 0x8000) + b"\x15" + b"\x00" * 10
            + b"ijklmnopqrst\x00" + b"mysql_native_password\x00")
    return struct.pack("<I", len(body))[:3] + b"\x00" + body


def banner_server(port: int, payload: bytes, wait_for_client: bool = False):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND, port))
    srv.listen(16)

    def handle(c):
        try:
            c.settimeout(5)
            c.sendall(payload)
            c.recv(1024)
        except OSError:
            pass
        finally:
            c.close()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


def ssh_server(port: int):
    """A real SSH endpoint with legacy algorithms and a short host key (logins always fail). Falls back to a
    version banner when paramiko is not installed."""
    try:
        import paramiko
    except ImportError:
        return banner_server(port, b"SSH-2.0-OpenSSH_7.4\r\n")

    class NoLogin(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "password"

        def check_auth_password(self, username, password):
            return paramiko.AUTH_FAILED

    host_key = paramiko.RSAKey.generate(1024)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((BIND, port))
    srv.listen(16)

    def handle(c):
        try:
            t = paramiko.Transport(c)
            t.local_version = "SSH-2.0-OpenSSH_7.4"
            opts = t.get_security_options()
            opts.ciphers = ("aes128-ctr", "aes128-cbc", "3des-cbc")
            opts.digests = ("hmac-sha1", "hmac-md5")
            t.add_server_key(host_key)
            t.start_server(server=NoLogin())
            t.join(20)
        except Exception:  # noqa: BLE001
            pass
        finally:
            c.close()

    while True:
        c, _ = srv.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()


# ------------------------------------------------------------------ certificates
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_certs():
    CERT_DIR.mkdir(parents=True, exist_ok=True)
    CA_DIR.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(_name("OpenASV Demo CA")).issuer_name(_name("OpenASV Demo CA"))
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=825))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                       key_encipherment=False, data_encipherment=False, key_agreement=False,
                                       encipher_only=False, decipher_only=False), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .sign(ca_key, hashes.SHA256()))
    key = ec.generate_private_key(ec.SECP256R1())
    if WEAK:  # self-signed and expired
        nb, na, issuer, signer = now - dt.timedelta(days=400), now - dt.timedelta(days=30), _name(HOST), key
    else:
        nb, na, issuer, signer = now - dt.timedelta(days=1), now + dt.timedelta(days=365), ca.subject, ca_key
    names = [x509.DNSName(HOST), x509.DNSName("localhost")] + [x509.DNSName(n) for n in os.environ.get("DEMO_SANS", "").split(",") if n]
    leaf = (x509.CertificateBuilder().subject_name(_name(HOST)).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(na)
            .add_extension(x509.SubjectAlternativeName(names), critical=False)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(signer, hashes.SHA256()))
    (CERT_DIR / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                         serialization.NoEncryption()))
    chain = leaf.public_bytes(serialization.Encoding.PEM) + (b"" if WEAK else ca.public_bytes(serialization.Encoding.PEM))
    (CERT_DIR / "cert.pem").write_bytes(chain)
    (CA_DIR / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))


def tls_context() -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    if WEAK:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    else:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.load_cert_chain(CERT_DIR / "cert.pem", CERT_DIR / "key.pem")
    return ctx


if __name__ == "__main__":
    if WEAK:
        WSGIRequestHandler.server_version, WSGIRequestHandler.sys_version = "Werkzeug/2.0.1", "Python/3.8.10"
    else:
        WSGIRequestHandler.server_version, WSGIRequestHandler.sys_version = "storefront", ""
    make_certs()
    servers = [make_server(BIND, HTTPS_PORT, app, threaded=True, ssl_context=tls_context())]
    if WEAK:
        servers.append(make_server(BIND, HTTP_PORT, app, threaded=True))
        threading.Thread(target=banner_server, args=(MYSQL_PORT, mysql_greeting()), daemon=True).start()
        threading.Thread(target=ssh_server, args=(SSH_PORT,), daemon=True).start()
    for s in servers[1:]:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    print(f"demo-target mode={MODE} https={HTTPS_PORT}" + (f" http={HTTP_PORT} mysql={MYSQL_PORT} ssh={SSH_PORT}" if WEAK else ""), flush=True)
    servers[0].serve_forever()
