"""WSGI app factory and routes.

Two surfaces share one process:

* The **public** surface (home, privacy, verify, operator console) uses the
  house shell and the Kituwa network bar.
* The **secret** surface (`/l/<id>`, `/m/<id>`, `/api/links/*`) is deliberately
  bare: no bar, no analytics, no third-party origin, no cookies, and a CSP that
  allows nothing but this origin. A single script on that page could read the
  key out of ``location.hash``, so the page ships one file and nothing else.

There are no accounts. The only session in the process belongs to an operator
who signed in to the console with Pocket ID.
"""
from __future__ import annotations

import base64
import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, send_from_directory, session, url_for)

from . import db, limits, oidc, security, store
from .config import Settings

SECRET_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; "
    "frame-ancestors 'none'; form-action 'self'"
)
PUBLIC_CSP = (
    "default-src 'self'; script-src 'self' https://hub.kituwa.com; "
    "style-src 'self' https://hub.kituwa.com; img-src 'self' data: https://hub.kituwa.com; "
    "connect-src 'self' https://hub.kituwa.com https://id.kituwa.com; "
    "font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
    "form-action 'self'"
)
SECRET_PREFIXES = ("/l/", "/m/", "/api/")
SECRET_ENDPOINTS = {"open_link", "manage_page", "api_create", "api_consume",
                    "api_peek", "api_report", "api_manage", "api_pow", "api_config"}


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
        SEND_FILE_MAX_AGE_DEFAULT=0,   # always revalidate: a deploy must take effect
        SESSION_COOKIE_NAME="sl_admin",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=settings.cookie_secure,
        PERMANENT_SESSION_LIFETIME=12 * 3600,
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

    def admin_ok() -> bool:
        return bool(session.get("admin"))

    def admin_require():
        if not admin_ok():
            return redirect(url_for("admin_login"))
        return None

    def csrf_token() -> str:
        admin = session.get("admin") or {}
        return admin.get("csrf", "")

    def check_csrf() -> None:
        sent = request.form.get("csrf", "") or request.headers.get("X-CSRF-Token", "")
        expected = csrf_token()
        if not expected or not sent or not security.hmac.compare_digest(sent, expected):
            abort(400, "Bad or missing CSRF token.")

    def bucket_key() -> str:
        forwarded = request.headers.get("X-Forwarded-For") if settings.behind_proxy else None
        ip = security.client_ip(request.remote_addr, forwarded)
        return security.bucket(settings.secret, ip)

    def today_fmt(value: str | None) -> str:
        return (value or "").replace("T", " ")[:19]

    app.jinja_env.filters["dt"] = today_fmt
    app.jinja_env.globals.update(csrf_token=csrf_token, base_url=settings.base_url,
                                 sri=sri, repo_url=settings.repo_url,
                                 admin_signed_in=admin_ok)

    @app.after_request
    def _headers(resp: Response):
        secret = request.path.startswith(SECRET_PREFIXES) or request.endpoint in SECRET_ENDPOINTS
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

    # --- public pages -----------------------------------------------------
    @app.get("/healthz")
    def healthz():
        conn().execute("SELECT 1").fetchone()
        return jsonify(ok=True, service="links-kituwa")

    @app.get("/robots.txt")
    def robots():
        body = "User-agent: *\nAllow: /$\nDisallow: /l/\nDisallow: /m/\nDisallow: /api/\n"
        return Response(body, mimetype="text/plain")

    @app.get("/.well-known/security.txt")
    def security_txt():
        body = (
            "Contact: https://github.com/CrystalRockMarket/links-kituwa/issues\n"
            "Expires: 2027-11-26T00:00:00.000Z\n"
            "Preferred-Languages: en\n"
            "Canonical: https://links.kituwa.com/.well-known/security.txt\n"
            "# This service cannot read link contents; reports about a link can be sent\n"
            "# from the link page itself, with the destination only if you paste it.\n"
        )
        return Response(body, mimetype="text/plain")

    @app.get("/")
    def home():
        return render_template("home.html")

    @app.get("/privacy")
    def privacy():
        return render_template("privacy.html")

    # --- release provenance ----------------------------------------------
    def _release() -> dict:
        folder = settings.release_dir or (settings.data_dir / "release")
        out: dict = {"repo": settings.repo_url}
        try:
            out.update(json.loads((folder / "release.json").read_text()))
        except (OSError, ValueError):
            out.setdefault("version", "dev")
        try:
            out["deployed"] = json.loads((folder / "state.json").read_text())
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
        if not limiter.allow("create", bucket_key()):
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

    # --- operator console (Pocket ID, operators group) --------------------
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
            "reports": c.execute("SELECT COUNT(*) c FROM reports WHERE resolved=0").fetchone()["c"],
            "reported": c.execute("SELECT COUNT(*) c FROM links WHERE reported=1").fetchone()["c"],
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
                            "name": claims.get("name", ""), "csrf": security.new_token(16)}
        session.permanent = True
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

    # --- error pages ------------------------------------------------------
    @app.errorhandler(404)
    def not_found(_exc):
        if request.path.startswith("/api/"):
            return jsonify(error="not found"), 404
        if request.path.startswith(("/l/", "/m/")):
            return render_template("gone.html", reason="No such link."), 404
        return render_template("notfound.html"), 404

    @app.errorhandler(413)
    def too_large(_exc):
        return jsonify(error="request body is too large"), 413

    @app.errorhandler(500)
    def server_error(_exc):
        app.logger.exception("unhandled error")
        return render_template("message.html", title="Something went wrong",
                               body="The request failed. Nothing was stored."), 500

    return app


def make_app() -> Flask:
    from .config import load_settings
    return create_app(load_settings())
