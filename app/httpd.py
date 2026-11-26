"""WSGI app factory and routes.

Two surfaces share one process:

* The **public** surface (home, create, privacy, verify, accounts, admin) uses
  the house shell and the Kituwa network bar.
* The **secret** surface (`/l/<id>`, `/m/<id>`, `/api/links/*`) is deliberately
  bare: no bar, no analytics, no third-party origin, no cookies, and a CSP that
  allows nothing but this origin. A single script on that page could read the
  key out of ``location.hash``, so the page ships one file and nothing else.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import sqlite3
import threading
import time
from functools import wraps
from pathlib import Path

from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)

from . import db, limits, mail, oidc, security, store
from .config import Settings

SECRET_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'"
)
PUBLIC_CSP = (
    "default-src 'self'; script-src 'self' https://hub.kituwa.com; "
    "style-src 'self' https://hub.kituwa.com; img-src 'self' data: https://hub.kituwa.com; "
    "connect-src 'self' https://hub.kituwa.com; font-src 'self'; object-src 'none'; "
    "base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
)
SECRET_PREFIXES = ("/l/", "/m/", "/api/", "/s/")
RESERVED = {
    "privacy", "verify", "release.json", "release.json.sig", "release.pub", "release",
    "robots.txt", "healthz", "login", "signup", "app", "admin", "api", "l", "m", "s",
    "static", "favicon.ico", "auth", "logout", "verify-email",
}
ACCOUNT_ENDPOINTS = {"login", "signup", "app_home", "link_detail", "settings_page",
                     "admin_home", "admin_login"}


def _b64d(value, field: str, limit: int) -> bytes:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a base64url string")
    pad = "=" * (-len(value) % 4)
    try:
        raw = base64.urlsafe_b64decode(value + pad)
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"{field} is not base64url") from exc
    if len(raw) > limit:
        raise ValueError(f"{field} is too large")
    return raw


def _b64e(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def create_app(settings: Settings) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config.update(
        SECRET_KEY=settings.secret,
        MAX_CONTENT_LENGTH=settings.max_body,
        SESSION_COOKIE_NAME="sl_sid",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.cookie_secure,
        PERMANENT_SESSION_LIFETIME=settings.session_days * 86400,
        SETTINGS=settings,
        JSON_SORT_KEYS=False,
    )
    changes = db.init_db(db.db_path(settings.data_dir))
    if changes:
        app.logger.warning("database migrated: %s", ", ".join(changes))

    limiter = limits.Limiter()
    static_dir = Path(app.static_folder or "static")
    sri_cache: dict[str, str] = {}

    def sri(filename: str) -> str:
        if filename not in sri_cache:
            data = (static_dir / filename).read_bytes()
            sri_cache[filename] = "sha384-" + base64.b64encode(
                hashlib.sha384(data).digest()).decode()
        return sri_cache[filename]

    # --- retention sweeper -------------------------------------------------
    if settings.sweep and not app.testing:
        def _loop() -> None:
            while True:
                try:
                    c = db.connect(db.db_path(settings.data_dir))
                    try:
                        store.sweep(c)
                    finally:
                        c.close()
                    limiter.prune()
                except Exception:  # noqa: BLE001
                    app.logger.exception("sweeper failed")
                time.sleep(60)

        threading.Thread(target=_loop, name="links-sweeper", daemon=True).start()

    # --- plumbing ---------------------------------------------------------
    def conn() -> sqlite3.Connection:
        if "conn" not in g:
            g.conn = db.connect(db.db_path(settings.data_dir))
        return g.conn

    @app.teardown_appcontext
    def _close(_exc):
        c = g.pop("conn", None)
        if c is not None:
            c.close()

    @app.before_request
    def _load_session():
        g.account = None
        if request.endpoint in ACCOUNT_ENDPOINTS and "anon_csrf" not in session:
            session["anon_csrf"] = security.new_token(16)
        token = session.get("sid")
        if not token:
            return
        row = conn().execute(
            "SELECT s.csrf, s.expires_at, a.id AS id, a.email, a.notify_email, "
            "a.email_verified FROM sessions s JOIN accounts a ON a.id = s.account_id "
            "WHERE s.token=? AND s.expires_at > ?",
            (security.token_digest(token), security.utcnow()),
        ).fetchone()
        if row is None:
            session.clear()
            return
        g.account = row

    @app.after_request
    def _headers(resp: Response):
        secret = request.path.startswith(SECRET_PREFIXES) or request.endpoint in {
            "open_link", "manage_page", "api_create", "api_consume", "api_peek",
            "api_report", "api_manage", "api_pow", "api_config"}
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.headers.setdefault(
            "Permissions-Policy",
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), "
            "interest-cohort=(), browsing-topics=()")
        resp.headers.setdefault("Strict-Transport-Security",
                                "max-age=63072000; includeSubDomains; preload")
        resp.headers.setdefault("Content-Security-Policy",
                                SECRET_CSP if secret else PUBLIC_CSP)
        if secret:
            resp.headers["Cache-Control"] = "no-store, max-age=0"
            resp.headers.pop("Set-Cookie", None)
        return resp

    def csrf_token() -> str:
        return g.account["csrf"] if g.account else session.get("anon_csrf", "")

    def check_csrf() -> None:
        sent = request.form.get("csrf", "") or request.headers.get("X-CSRF-Token", "")
        expected = csrf_token()
        if not expected or not sent or not security.hmac.compare_digest(sent, expected):
            abort(400, "Bad or missing CSRF token.")

    def login_required(view):
        @wraps(view)
        def inner(*a, **kw):
            if g.account is None:
                return redirect(url_for("login", next=request.path))
            return view(*a, **kw)
        return inner

    def bucket_key() -> str:
        forwarded = request.headers.get("X-Forwarded-For") if settings.behind_proxy else None
        ip = security.client_ip(request.remote_addr, forwarded)
        return security.bucket(settings.secret, ip)

    def today_fmt(value: str | None) -> str:
        return (value or "").replace("T", " ")[:19]

    app.jinja_env.filters["dt"] = today_fmt
    app.jinja_env.globals.update(csrf_token=csrf_token, base_url=settings.base_url,
                                 sri=sri, repo_url=settings.repo_url)

    # --- public pages -----------------------------------------------------
    @app.get("/healthz")
    def healthz():
        conn().execute("SELECT 1").fetchone()
        return jsonify(ok=True, service="links-kituwa")

    @app.get("/robots.txt")
    def robots():
        body = "User-agent: *\nAllow: /$\nDisallow: /l/\nDisallow: /m/\nDisallow: /api/\n"
        return Response(body, mimetype="text/plain")

    @app.get("/")
    def home():
        if g.account:
            return redirect(url_for("app_home"))
        return render_template("home.html", signed_in=False)

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html")

    # --- release provenance ----------------------------------------------
    def _release() -> dict:
        folder = settings.release_dir or (settings.data_dir / "release")
        manifest = folder / "release.json"
        state = folder / "state.json"
        out: dict = {"repo": settings.repo_url}
        try:
            out.update(json.loads(manifest.read_text()))
        except (OSError, ValueError):
            out.setdefault("version", "dev")
        try:
            out["deployed"] = json.loads(state.read_text())
        except (OSError, ValueError):
            out["deployed"] = {}
        return out

    @app.get("/verify")
    def verify_page():
        return render_template("verify.html", release=_release())

    @app.get("/release.json")
    def release_manifest():
        folder = settings.release_dir or (settings.data_dir / "release")
        path = folder / "release.json"
        if not path.exists():
            return jsonify(error="no release manifest"), 404
        return Response(path.read_bytes(), mimetype="application/json")

    @app.get("/release.json.sig")
    def release_sig():
        folder = settings.release_dir or (settings.data_dir / "release")
        path = folder / "release.json.sig"
        if not path.exists():
            return jsonify(error="no signature"), 404
        return Response(path.read_bytes(), mimetype="application/octet-stream")

    @app.get("/release.pub")
    def release_pub():
        folder = settings.release_dir or (settings.data_dir / "release")
        path = folder / "release.pub"
        if not path.exists():
            return jsonify(error="no public key"), 404
        return Response(path.read_bytes(), mimetype="text/plain")

    @app.get("/release/<name>")
    def release_artifact(name: str):
        folder = settings.release_dir or (settings.data_dir / "release")
        if not name.startswith("links-kituwa-") or not name.endswith(".tar.gz") \
                or "/" in name or ".." in name:
            abort(404)
        return send_from_directory(folder, name, as_attachment=True,
                                   mimetype="application/gzip")

    # --- the zero-knowledge API -------------------------------------------
    @app.get("/api/config")
    def api_config():
        return jsonify(pow=settings.pow and limiter.under_pressure(),
                       max_bytes=store.MAX_CIPHERTEXT,
                       max_uses=store.MAX_USES,
                       max_expiry=store.MAX_EXPIRY_S)

    @app.get("/api/pow")
    def api_pow():
        return jsonify(**limits.challenge(settings.secret))

    @app.post("/api/links")
    def api_create():
        key = bucket_key()
        if not limiter.allow("create", key):
            return jsonify(error="Too many links from here. Try again later."), 429
        body = request.get_json(silent=True) or {}
        if settings.pow and limiter.under_pressure():
            proof = body.get("pow") or {}
            if not limits.verify(settings.secret, proof.get("challenge", ""),
                                 proof.get("solution", "")):
                return jsonify(error="proof of work required", pow=True), 428
        opts = body.get("options") or {}
        try:
            ciphertext = _b64d(body.get("ciphertext"), "ciphertext", store.MAX_CIPHERTEXT)
            iv = _b64d(body.get("iv"), "iv", 12)
            salt_raw = body.get("salt")
            salt = _b64d(salt_raw, "salt", 16) if salt_raw else None
            kdf = str(body.get("kdf") or "none")
            max_uses = opts.get("max_uses")
            max_uses = int(max_uses) if max_uses not in (None, "", 0) else None
            expires_in = int(opts["expires_in"]) if opts.get("expires_in") else None
            not_before_in = int(opts.get("not_before_in") or 0)
            link_id, token = store.create(
                conn(), ciphertext=ciphertext, iv=iv, salt=salt, kdf=kdf,
                max_uses=max_uses, expires_in=expires_in, not_before_in=not_before_in,
                redirect_mode=str(opts.get("redirect_mode") or "auto"),
                has_note=bool(opts.get("has_note")),
            )
        except (ValueError, TypeError) as exc:
            return jsonify(error=str(exc)), 400
        return jsonify(id=link_id, manage_token=token,
                       url=f"{settings.base_url}/l/{link_id}"), 201

    @app.post("/api/links/<link_id>/consume")
    def api_consume(link_id: str):
        if not security.valid_id(link_id):
            return jsonify(error="no such link"), 404
        if not limiter.allow("consume", bucket_key()):
            return jsonify(error="Too many opens from here. Slow down."), 429
        result = store.consume(conn(), link_id)
        if result.state != "ok":
            return jsonify(error="gone", reason=result.reason), (
                404 if result.state == "missing" else 410)
        return jsonify(ciphertext=_b64e(result.ciphertext or b""),
                       iv=_b64e(result.iv or b""),
                       salt=_b64e(result.salt) if result.salt else None,
                       kdf=result.kdf, redirect_mode=result.redirect_mode,
                       uses_left=result.uses_left, max_uses=result.max_uses)

    @app.get("/api/links/<link_id>")
    def api_peek(link_id: str):
        if not security.valid_id(link_id):
            return jsonify(error="no such link"), 404
        state = store.peek(conn(), link_id)
        return jsonify(state), (200 if state.get("exists") else 404)

    @app.post("/api/links/<link_id>/report")
    def api_report(link_id: str):
        if not limiter.allow("report", bucket_key()):
            return jsonify(error="Too many reports from here."), 429
        if not security.valid_id(link_id):
            return jsonify(error="no such link"), 404
        body = request.get_json(silent=True) or {}
        url = body.get("url")
        if url and (not isinstance(url, str) or len(url) > 2048):
            url = None
        ok = store.report(conn(), link_id, str(body.get("reason") or ""), url)
        return jsonify(ok=ok), (200 if ok else 404)

    @app.post("/api/manage/<link_id>")
    def api_manage(link_id: str):
        if not limiter.allow("manage", bucket_key()):
            return jsonify(error="Too many requests."), 429
        if not security.valid_id(link_id):
            return jsonify(error="no such link"), 404
        body = request.get_json(silent=True) or {}
        seconds = body.get("seconds")
        result = store.manage(conn(), link_id, str(body.get("token") or ""),
                              str(body.get("action") or "state"),
                              int(seconds) if seconds else None)
        return jsonify(result), (200 if result.get("ok") else 404)

    # --- the secret surfaces ---------------------------------------------
    @app.get("/l/<link_id>")
    def open_link(link_id: str):
        if not security.valid_id(link_id):
            return render_template("gone.html", reason="No such link."), 404
        return render_template("l.html", link_id=link_id)

    @app.get("/m/<link_id>")
    def manage_page(link_id: str):
        if not security.valid_id(link_id):
            return render_template("gone.html", reason="No such link."), 404
        return render_template("m.html", link_id=link_id)

    # --- legacy links (created before 2026-11-26) -------------------------
    @app.get("/<code>")
    def open_legacy(code: str):
        if code in RESERVED or not security.valid_code(code):
            return render_template("gone.html", reason="No such link."), 404
        ua = request.headers.get("User-Agent", "")
        purpose = request.headers.get("Sec-Purpose", "") or request.headers.get("Purpose", "")
        if security.is_preview(ua, purpose):
            return render_template("preview.html", code=code)
        result = store.legacy_consume(conn(), code)
        if result.state != "ok":
            return render_template("gone.html", reason="This link has expired or been used."), 410
        resp = redirect(result.ciphertext.decode(), code=302)
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp

    @app.get("/s/<code>")
    def open_legacy_alias(code: str):
        return open_legacy(code)

    # --- accounts (kept for the legacy dashboard) -------------------------
    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if not settings.allow_signup:
            return render_template("message.html", title="Signups are closed",
                                   body="Accounts are invite-only right now."), 403
        if settings.mailbox_mode == "none":
            return render_template(
                "message.html", title="Use Pocket ID to sign up",
                body="Email accounts open once transactional mail is configured. Until "
                     "then, sign in with Pocket ID — it creates your account in one click."), 503
        error = ""
        if request.method == "POST":
            check_csrf()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            if "@" not in email or len(email) > 254:
                error = "Enter a valid email address."
            elif len(password) < 12:
                error = "Use at least 12 characters."
            else:
                try:
                    cur = conn().execute(
                        "INSERT INTO accounts(email, pw_hash, created_at, notify_email) VALUES (?,?,?,?)",
                        (email, security.hash_password(password), security.utcnow(), email),
                    )
                    account_id = int(cur.lastrowid)
                    token = security.new_token()
                    conn().execute(
                        "INSERT INTO verify_tokens(token, account_id, expires_at) VALUES (?,?,?)",
                        (security.token_digest(token), account_id, security.iso_after(days=2)),
                    )
                    link = f"{settings.base_url}/verify-email/{token}"
                    mail.send(settings.data_dir, settings.mail_from, email,
                              "Confirm your links.kituwa.com account",
                              f"Open this link to confirm your account:\n\n{link}\n",
                              settings.smtp_host)
                    return redirect(url_for("signup_sent"))
                except sqlite3.IntegrityError:
                    error = "An account with that email already exists."
        return render_template("signup.html", error=error), (400 if error else 200)

    @app.get("/signup/sent")
    def signup_sent():
        return render_template("message.html", title="Check your mail",
                               body="We sent a confirmation link. It expires in 2 days.")

    @app.get("/verify-email/<token>")
    def verify_email(token: str):
        row = conn().execute(
            "SELECT * FROM verify_tokens WHERE token=? AND used=0 AND expires_at > ?",
            (security.token_digest(token), security.utcnow()),
        ).fetchone()
        if row is None:
            return render_template("message.html", title="Link expired",
                                   body="That confirmation link is no longer valid."), 410
        conn().execute("UPDATE verify_tokens SET used=1 WHERE token=?", (row["token"],))
        conn().execute("UPDATE accounts SET email_verified=1 WHERE id=?", (row["account_id"],))
        return render_template("message.html", title="Email confirmed",
                               body="Your account is ready. Sign in to see your links.")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            check_csrf()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            ip = security.client_ip(request.remote_addr,
                                    request.headers.get("X-Forwarded-For")
                                    if settings.behind_proxy else None)
            key = f"{security.token_digest(email)}:{security.bucket(settings.secret, ip)}"
            if not limiter.allow("login", key):
                return render_template("login.html",
                                       error="Too many attempts. Wait 15 minutes."), 429
            row = conn().execute("SELECT * FROM accounts WHERE email=?", (email,)).fetchone()
            if row and security.verify_password(row["pw_hash"], password):
                token = security.new_token()
                csrf = security.new_token(16)
                conn().execute(
                    "INSERT INTO sessions(token, account_id, csrf, created_at, expires_at) "
                    "VALUES (?,?,?,?,?)",
                    (security.token_digest(token), row["id"], csrf,
                     security.utcnow(), security.iso_after(days=settings.session_days)),
                )
                session.clear()
                session.permanent = True
                session["sid"] = token
                if security.needs_rehash(row["pw_hash"]):
                    conn().execute("UPDATE accounts SET pw_hash=? WHERE id=?",
                                   (security.hash_password(password), row["id"]))
                nxt = request.args.get("next") or ""
                return redirect(nxt if nxt.startswith("/app") else url_for("app_home"))
            error = "Email or password is not correct."
        return render_template("login.html", error=error), (401 if error else 200)

    def start_session(account_row) -> None:
        token = security.new_token()
        csrf = security.new_token(16)
        conn().execute(
            "INSERT INTO sessions(token, account_id, csrf, created_at, expires_at) "
            "VALUES (?,?,?,?,?)",
            (security.token_digest(token), account_row["id"], csrf,
             security.utcnow(), security.iso_after(days=settings.session_days)),
        )
        session.clear()
        session.permanent = True
        session["sid"] = token

    @app.get("/auth/pocketid")
    def member_login():
        if not settings.member_client_id:
            return render_template("message.html", title="Sign-in is not configured",
                                   body="Pocket ID sign-in is not wired to this service yet."), 503
        try:
            flow = oidc.begin(settings.oidc_issuer, settings.member_client_id,
                              settings.base_url + "/auth/pocketid/callback",
                              settings.oidc_internal_base or None)
        except Exception:  # noqa: BLE001
            return render_template("message.html", title="Identity provider unreachable",
                                   body="Pocket ID did not answer. Try again in a moment."), 503
        session["oidc_member"] = {"state": flow["state"], "nonce": flow["nonce"],
                                  "verifier": flow["verifier"],
                                  "token_endpoint": flow["token_endpoint"]}
        return redirect(flow["url"])

    @app.get("/auth/pocketid/callback")
    def member_callback():
        flow = session.pop("oidc_member", None)
        if not flow:
            abort(400, "No sign-in in progress.")
        if request.args.get("state") != flow["state"]:
            abort(400, "State mismatch.")
        code = request.args.get("code")
        if not code:
            abort(400, "No authorization code.")
        try:
            tokens = oidc.exchange(flow["token_endpoint"], code,
                                   settings.base_url + "/auth/pocketid/callback",
                                   settings.member_client_id, settings.member_client_secret,
                                   flow["verifier"])
            claims = oidc.verify_id_token(
                tokens["id_token"],
                oidc.jwks(settings.oidc_issuer, settings.oidc_internal_base or None),
                settings.oidc_issuer, settings.member_client_id, nonce=flow["nonce"])
        except (oidc.OIDCError, KeyError, ValueError):
            return render_template("message.html", title="Sign-in failed",
                                   body="The identity provider rejected this sign-in."), 401
        email = (claims.get("email") or "").strip().lower()
        if not email or "@" not in email:
            return render_template("message.html", title="No email on that account",
                                   body="Pocket ID did not return an email address, so no "
                                        "account can be matched to it."), 403
        row = conn().execute("SELECT * FROM accounts WHERE email=?", (email,)).fetchone()
        if row is None:
            cur = conn().execute(
                "INSERT INTO accounts(email, pw_hash, created_at, email_verified, notify_email) "
                "VALUES (?,?,?,1,?)",
                (email, "!pocketid", security.utcnow(), email))
            row = conn().execute("SELECT * FROM accounts WHERE id=?",
                                 (int(cur.lastrowid),)).fetchone()
        elif not row["email_verified"]:
            conn().execute("UPDATE accounts SET email_verified=1 WHERE id=?", (row["id"],))
        start_session(row)
        return redirect(url_for("app_home"))

    @app.post("/logout")
    def logout():
        check_csrf()
        token = session.get("sid")
        if token:
            conn().execute("DELETE FROM sessions WHERE token=?",
                           (security.token_digest(token),))
        session.clear()
        return redirect(url_for("home"))

    # --- operator console (Pocket ID, operators group) --------------------
    def admin_ok() -> bool:
        return bool(session.get("admin"))

    def admin_require():
        if not admin_ok():
            return redirect(url_for("admin_login"))
        return None

    @app.get("/admin")
    def admin_home():
        gate = admin_require()
        if gate is not None:
            return gate
        c = conn()
        stats = {
            "links": c.execute("SELECT COUNT(*) c FROM links").fetchone()["c"],
            "active": c.execute(
                "SELECT COUNT(*) c FROM links WHERE spent_at IS NULL AND disabled_at IS NULL "
                "AND (expires_at IS NULL OR expires_at > ?) AND (max_uses IS NULL OR uses < max_uses)",
                (security.utcnow(),)).fetchone()["c"],
            "spent": c.execute("SELECT COUNT(*) c FROM links WHERE spent_at IS NOT NULL").fetchone()["c"],
            "legacy": c.execute("SELECT COUNT(*) c FROM legacy_links").fetchone()["c"],
            "reports": c.execute("SELECT COUNT(*) c FROM reports WHERE resolved=0").fetchone()["c"],
            "accounts": c.execute("SELECT COUNT(*) c FROM accounts").fetchone()["c"],
        }
        links = c.execute(
            "SELECT id, uses, max_uses, created_at, expires_at, spent_at, disabled_at, reported "
            "FROM links ORDER BY created_at DESC LIMIT 50").fetchall()
        reports = c.execute(
            "SELECT * FROM reports WHERE resolved=0 ORDER BY id DESC LIMIT 50").fetchall()
        return render_template("admin.html", stats=stats, links=links, reports=reports,
                               who=session.get("admin", {}))

    @app.get("/admin/login")
    def admin_login():
        if not settings.oidc_client_id:
            return render_template("message.html", title="Operator sign-in is not configured",
                                   body="No Pocket ID client is wired to this service."), 503
        try:
            flow = oidc.begin(settings.oidc_issuer, settings.oidc_client_id,
                              settings.base_url + "/admin/oidc/callback",
                              settings.oidc_internal_base or None)
        except Exception:  # noqa: BLE001
            return render_template("message.html", title="Identity provider unreachable",
                                   body="Pocket ID did not answer. Try again in a moment."), 503
        session["oidc"] = {"state": flow["state"], "nonce": flow["nonce"],
                           "verifier": flow["verifier"],
                           "token_endpoint": flow["token_endpoint"]}
        return redirect(flow["url"])

    @app.get("/admin/oidc/callback")
    def admin_callback():
        flow = session.pop("oidc", None)
        if not flow:
            abort(400, "No sign-in in progress.")
        if request.args.get("state") != flow["state"]:
            abort(400, "State mismatch.")
        code = request.args.get("code")
        if not code:
            abort(400, "No authorization code.")
        try:
            tokens = oidc.exchange(flow["token_endpoint"], code,
                                   settings.base_url + "/admin/oidc/callback",
                                   settings.oidc_client_id, settings.oidc_client_secret,
                                   flow["verifier"])
            claims = oidc.verify_id_token(
                tokens["id_token"],
                oidc.jwks(settings.oidc_issuer, settings.oidc_internal_base or None),
                settings.oidc_issuer, settings.oidc_client_id, nonce=flow["nonce"])
        except (oidc.OIDCError, KeyError, ValueError):
            return render_template("message.html", title="Sign-in failed",
                                   body="The identity provider rejected this sign-in."), 401
        if not oidc.has_group(claims, settings.oidc_group):
            return render_template("message.html", title="Not an operator",
                                   body="This account is not in the operators group."), 403
        session["admin"] = {"sub": claims.get("sub", ""), "email": claims.get("email", ""),
                            "name": claims.get("name", "")}
        return redirect(url_for("admin_home"))

    @app.post("/admin/logout")
    def admin_logout():
        check_csrf()
        session.pop("admin", None)
        return redirect(url_for("home"))

    @app.post("/admin/disable/<link_id>")
    def admin_disable(link_id: str):
        gate = admin_require()
        if gate is not None:
            return gate
        check_csrf()
        store.disable(conn(), link_id)
        return redirect(url_for("admin_home"))

    @app.post("/admin/report/<int:report_id>/resolve")
    def admin_resolve(report_id: int):
        gate = admin_require()
        if gate is not None:
            return gate
        check_csrf()
        conn().execute("UPDATE reports SET resolved=1 WHERE id=?", (report_id,))
        return redirect(url_for("admin_home"))

    # --- legacy dashboard -------------------------------------------------
    @app.get("/app")
    @login_required
    def app_home():
        links = conn().execute(
            "SELECT * FROM legacy_links WHERE account_id=? ORDER BY id DESC",
            (g.account["id"],)).fetchall()
        return render_template("app.html", links=links)

    def owned_legacy(link_id: int) -> sqlite3.Row:
        row = conn().execute("SELECT * FROM legacy_links WHERE id=? AND account_id=?",
                             (link_id, g.account["id"])).fetchone()
        if row is None:
            abort(404)
        return row

    @app.get("/app/link/<int:link_id>")
    @login_required
    def link_detail(link_id: int):
        link = owned_legacy(link_id)
        return render_template("link.html", link=link, state=store.legacy_state_of(link))

    @app.post("/app/link/<int:link_id>/<action>")
    @login_required
    def link_action(link_id: int, action: str):
        check_csrf()
        link = owned_legacy(link_id)
        now = security.utcnow()
        if action == "destroy":
            conn().execute("UPDATE legacy_links SET destroyed_at=? WHERE id=?", (now, link["id"]))
        elif action == "pause":
            conn().execute("UPDATE legacy_links SET disabled_at=? WHERE id=?", (now, link["id"]))
        elif action == "resume":
            conn().execute("UPDATE legacy_links SET disabled_at=NULL, destroyed_at=NULL WHERE id=?",
                           (link["id"],))
        else:
            abort(404)
        return redirect(url_for("link_detail", link_id=link["id"]))

    @app.route("/app/settings", methods=["GET", "POST"])
    @login_required
    def settings_page():
        if request.method == "POST":
            check_csrf()
            notify = (request.form.get("notify_email") or "").strip().lower()
            conn().execute("UPDATE accounts SET notify_email=? WHERE id=?",
                           (notify or g.account["email"], g.account["id"]))
            return redirect(url_for("app_home"))
        return render_template("settings.html")

    return app


def make_app() -> Flask:
    from .config import load_settings
    return create_app(load_settings())
