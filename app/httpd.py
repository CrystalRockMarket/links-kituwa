"""WSGI app factory and routes."""
from __future__ import annotations

import html
import json
import sqlite3
from functools import wraps

from flask import (Flask, Response, abort, g, jsonify, redirect, render_template,
                   request, session, url_for)

from . import db, mail, oidc, security, tracking
from .config import Settings


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
    )
    db.init_db(db.db_path(settings.data_dir))

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
        if "anon_csrf" not in session:
            session["anon_csrf"] = security.new_token(16)
        token = session.get("sid")
        if not token:
            return
        row = conn().execute(
            "SELECT s.csrf, s.expires_at, a.id AS id, a.email, a.notify_email, "
            "a.default_uses, a.alerts, a.email_verified "
            "FROM sessions s JOIN accounts a ON a.id = s.account_id "
            "WHERE s.token=? AND s.expires_at > ?",
            (security.token_digest(token), security.utcnow()),
        ).fetchone()
        if row is None:
            session.clear()
            return
        g.account = row

    @app.after_request
    def _headers(resp: Response):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        )
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

    def today_fmt(value: str | None) -> str:
        return (value or "").replace("T", " ")[:19]

    app.jinja_env.filters["dt"] = today_fmt
    app.jinja_env.globals["csrf_token"] = csrf_token
    app.jinja_env.globals["base_url"] = settings.base_url

    # --- public pages -----------------------------------------------------
    @app.get("/healthz")
    def healthz():
        conn().execute("SELECT 1").fetchone()
        return jsonify(ok=True, service="secret-link")

    @app.get("/")
    def home():
        if g.account:
            return redirect(url_for("app_home"))
        return render_template("home.html", signed_in=False)

    # --- accounts ---------------------------------------------------------
    @app.route("/signup", methods=["GET", "POST"])
    def signup():
        if not settings.allow_signup:
            return render_template("message.html", title="Signups are closed",
                                   body="Accounts are invite-only right now."), 403
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
                    link = f"{settings.base_url}/verify/{token}"
                    mail.send(settings.data_dir, settings.mail_from, email,
                              "Confirm your Secret Link account",
                              f"Open this link to confirm your account:\n\n{link}\n", settings.smtp_host)
                    return redirect(url_for("signup_sent"))
                except sqlite3.IntegrityError:
                    error = "An account with that email already exists."
        return render_template("signup.html", error=error), (400 if error else 200)

    @app.get("/signup/sent")
    def signup_sent():
        return render_template("message.html", title="Check your mail",
                               body="We sent a confirmation link. It expires in 2 days.")

    @app.get("/verify/<token>")
    def verify(token: str):
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
                               body="Your account is ready. Sign in to start creating links.")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        error = ""
        if request.method == "POST":
            check_csrf()
            email = (request.form.get("email") or "").strip().lower()
            password = request.form.get("password") or ""
            key = f"{security.token_digest(email)}:{request.remote_addr or ''}"
            attempt = conn().execute("SELECT * FROM login_attempts WHERE key=?", (key,)).fetchone()
            if attempt and attempt["fails"] >= 8 and attempt["first_fail"] > security.iso_after(minutes=-15):
                return render_template("login.html", error="Too many attempts. Wait 15 minutes."), 429
            row = conn().execute("SELECT * FROM accounts WHERE email=?", (email,)).fetchone()
            if row and security.verify_password(row["pw_hash"], password):
                conn().execute("DELETE FROM login_attempts WHERE key=?", (key,))
                token = security.new_token()
                csrf = security.new_token(16)
                conn().execute(
                    "INSERT INTO sessions(token, account_id, csrf, created_at, expires_at) VALUES (?,?,?,?,?)",
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
            conn().execute(
                "INSERT INTO login_attempts(key, fails, first_fail) VALUES (?,1,?) "
                "ON CONFLICT(key) DO UPDATE SET fails=fails+1",
                (key, security.utcnow()),
            )
            error = "Email or password is not correct."
        return render_template("login.html", error=error), (401 if error else 200)

    @app.post("/logout")
    def logout():
        check_csrf()
        token = session.get("sid")
        if token:
            conn().execute("DELETE FROM sessions WHERE token=?", (security.token_digest(token),))
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
        today = security.utcnow()[:10]
        stats = {
            "accounts": conn().execute("SELECT COUNT(*) c FROM accounts").fetchone()["c"],
            "links": conn().execute("SELECT COUNT(*) c FROM links").fetchone()["c"],
            "active": conn().execute(
                "SELECT COUNT(*) c FROM links WHERE destroyed_at IS NULL AND disabled_at IS NULL "
                "AND (max_uses IS NULL OR uses < max_uses)").fetchone()["c"],
            "destroyed": conn().execute(
                "SELECT COUNT(*) c FROM links WHERE destroyed_at IS NOT NULL").fetchone()["c"],
            "opens": conn().execute("SELECT COUNT(*) c FROM opens WHERE kind='open'").fetchone()["c"],
            "today": conn().execute(
                "SELECT COUNT(*) c FROM opens WHERE kind='open' AND ts LIKE ?", (today + "%",)
            ).fetchone()["c"],
            "previews": conn().execute("SELECT COUNT(*) c FROM opens WHERE kind='preview'").fetchone()["c"],
            "alerts": conn().execute("SELECT COUNT(*) c FROM alerts").fetchone()["c"],
        }
        links = conn().execute(
            "SELECT l.*, a.email, (SELECT COUNT(*) FROM opens o WHERE o.link_id=l.id AND o.kind='open') ops "
            "FROM links l JOIN accounts a ON a.id=l.account_id ORDER BY l.id DESC LIMIT 50"
        ).fetchall()
        return render_template("admin.html", stats=stats, links=links,
                               who=session.get("admin", {}))

    @app.get("/admin/login")
    def admin_login():
        if not settings.oidc_client_id:
            return render_template("message.html", title="Operator sign-in is not configured",
                                   body="No Pocket ID client is wired to this service."), 503
        flow = oidc.begin(settings.oidc_issuer, settings.oidc_client_id,
                          settings.base_url + "/admin/oidc/callback")
        session["oidc"] = {"state": flow["state"], "nonce": flow["nonce"],
                           "verifier": flow["verifier"], "token_endpoint": flow["token_endpoint"]}
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
            claims = oidc.verify_id_token(tokens["id_token"], oidc.jwks(settings.oidc_issuer),
                                          settings.oidc_issuer, settings.oidc_client_id,
                                          nonce=flow["nonce"])
        except (oidc.OIDCError, KeyError, ValueError) as exc:
            return render_template("message.html", title="Sign-in failed",
                                   body="The identity provider rejected this sign-in."), 401
        if not oidc.has_group(claims, settings.oidc_group):
            return render_template("message.html", title="Not an operator",
                                   body="This account is not in the operators group."), 403
        session["admin"] = {"sub": claims.get("sub", ""),
                            "email": claims.get("email", ""),
                            "name": claims.get("name", "")}
        return redirect(url_for("admin_home"))

    @app.post("/admin/logout")
    def admin_logout():
        check_csrf()
        session.pop("admin", None)
        return redirect(url_for("home"))

    # --- dashboard --------------------------------------------------------
    @app.get("/app")
    @login_required
    def app_home():
        links = conn().execute(
            "SELECT l.*, (SELECT COUNT(*) FROM visitors v WHERE v.link_id=l.id) visitors "
            "FROM links l WHERE l.account_id=? ORDER BY l.id DESC", (g.account["id"],)
        ).fetchall()
        alerts = conn().execute(
            "SELECT * FROM alerts WHERE account_id=? ORDER BY id DESC LIMIT 20",
            (g.account["id"],),
        ).fetchall()
        return render_template("app.html", links=links, alerts=alerts)

    @app.post("/app/new")
    @login_required
    def create():
        check_csrf()
        raw_uses = (request.form.get("max_uses") or "").strip()
        try:
            max_uses = None if raw_uses.lower() in {"", "0", "unlimited", "inf"} else int(raw_uses)
        except ValueError:
            max_uses = None
        try:
            link = tracking.create_link(
                conn(), g.account["id"],
                target=request.form.get("target", ""),
                label=request.form.get("label", ""),
                max_uses=max_uses,
                mode="track" if max_uses is None else "destroy",
                expires_days=int(request.form["expires_days"]) if request.form.get("expires_days") else None,
            )
        except (ValueError, RuntimeError) as exc:
            return render_template("app.html", links=conn().execute(
                "SELECT l.*, (SELECT COUNT(*) FROM visitors v WHERE v.link_id=l.id) visitors "
                "FROM links l WHERE l.account_id=? ORDER BY l.id DESC", (g.account["id"],)
            ).fetchall(), alerts=[], error=str(exc)), 400
        return redirect(url_for("link_detail", link_id=link["id"]))

    def owned_link(link_id: int) -> sqlite3.Row:
        row = conn().execute("SELECT * FROM links WHERE id=? AND account_id=?",
                             (link_id, g.account["id"])).fetchone()
        if row is None:
            abort(404)
        return row

    @app.get("/app/link/<int:link_id>")
    @login_required
    def link_detail(link_id: int):
        link = owned_link(link_id)
        summary = tracking.link_summary(conn(), link_id)
        opens = conn().execute(
            "SELECT o.*, v.fp FROM opens o LEFT JOIN visitors v ON v.id=o.visitor_id "
            "WHERE o.link_id=? ORDER BY o.id DESC LIMIT 200", (link_id,)
        ).fetchall()
        shares = conn().execute(
            "SELECT s.*, v.fp, v.last_ip FROM share_tokens s JOIN visitors v ON v.id=s.visitor_id "
            "WHERE s.link_id=? ORDER BY s.created_at DESC", (link_id,)
        ).fetchall()
        return render_template("link.html", link=link, summary=summary,
                               opens=opens, shares=shares, state=tracking.state_of(link))

    @app.post("/app/link/<int:link_id>/<action>")
    @login_required
    def link_action(link_id: int, action: str):
        check_csrf()
        link = owned_link(link_id)
        now = security.utcnow()
        if action == "destroy":
            conn().execute("UPDATE links SET destroyed_at=? WHERE id=?", (now, link["id"]))
        elif action == "pause":
            conn().execute("UPDATE links SET disabled_at=? WHERE id=?", (now, link["id"]))
        elif action == "resume":
            conn().execute("UPDATE links SET disabled_at=NULL, destroyed_at=NULL WHERE id=?", (link["id"],))
        elif action == "alerts":
            conn().execute("UPDATE alerts SET seen=1 WHERE link_id=?", (link["id"],))
        else:
            abort(404)
        return redirect(url_for("link_detail", link_id=link["id"]))

    @app.route("/app/settings", methods=["GET", "POST"])
    @login_required
    def settings_page():
        if request.method == "POST":
            check_csrf()
            notify = (request.form.get("notify_email") or "").strip().lower()
            default_uses = max(1, min(100000, int(request.form.get("default_uses") or 1)))
            alerts = 1 if request.form.get("alerts") else 0
            conn().execute("UPDATE accounts SET notify_email=?, default_uses=?, alerts=? WHERE id=?",
                           (notify or g.account["email"], default_uses, alerts, g.account["id"]))
            return redirect(url_for("app_home"))
        return render_template("settings.html")

    # --- the short link surface -------------------------------------------
    # The public short URL is the bare path on links.kituwa.com: /<code>.
    # /s/<code> stays as an alias so earlier links and bookmarks keep working.
    @app.get("/<code>")
    def open_link(code: str):
        if not security.valid_code(code):
            return render_template("message.html", title="No such link",
                                   body="This short link does not exist."), 404
        ua = request.headers.get("User-Agent", "")
        lang = request.headers.get("Accept-Language", "")
        forced = request.args.get("go") == "1"
        preview = (not forced) and security.is_preview(ua, request.headers.get("Sec-Purpose", "")
                                                       or request.headers.get("Purpose", ""))
        ip = security.client_ip(request.remote_addr, request.headers.get("X-Forwarded-For"))
        result = tracking.consume(
            conn(), code,
            ip=ip, ua=ua, referer=request.headers.get("Referer", ""),
            lang=lang, via=(request.args.get("via") or "")[:64],
            preview=preview, skip_increment=(request.args.get("go") == "1"),
            secret=settings.secret, ip_mode=settings.ip_mode,
        )
        resp: Response
        if result.state == "ok" and result.interstitial:
            resp = Response(render_template("tracked.html", code=code, target=result.target),
                            mimetype="text/html")
        elif result.state == "ok":
            resp = redirect(result.target, code=302)
        elif result.state == "preview":
            resp = Response(render_template("preview.html", code=code), mimetype="text/html")
        elif result.state == "gone":
            resp = Response(render_template("gone.html", code=code,
                                            reason=result.reason), status=410, mimetype="text/html")
        else:
            resp = Response(render_template("message.html", title="No such link",
                                            body="This short link does not exist."),
                            status=404, mimetype="text/html")
        resp.headers["Cache-Control"] = "no-store, max-age=0"
        return resp

    @app.get("/s/<code>")
    def open_link_alias(code: str):
        return open_link(code)

    @app.post("/s/<code>/share")
    def share_link_alias(code: str):
        return share_link(code)

    @app.post("/<code>/share")
    def share_link(code: str):
        origin = request.headers.get("Origin") or ""
        if origin and origin.rstrip("/") != settings.base_url:
            abort(403)
        ua = request.headers.get("User-Agent", "")
        ip = security.client_ip(request.remote_addr, request.headers.get("X-Forwarded-For"))
        fp = security.fingerprint(settings.secret, ip, ua, request.headers.get("Accept-Language", ""))
        token = tracking.mint_share(conn(), code, fp)
        if token is None:
            return jsonify(ok=False, error="Open the link yourself before forwarding it."), 409
        return jsonify(ok=True, url=f"{settings.base_url}/{code}?via={token}")

    return app


def make_app() -> Flask:
    from .config import load_settings
    return create_app(load_settings())
