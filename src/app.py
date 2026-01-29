from __future__ import annotations

import base64
import hashlib
import os
import secrets
import time
from datetime import datetime, timedelta
from pathlib import Path

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for
from jwt import InvalidTokenError
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError

APP_DIR = Path(__file__).resolve().parent

app = Flask(
    __name__,
    template_folder=str(APP_DIR / "templates"),
    static_folder=str(APP_DIR / "static"),
)
if "FLASK_SECRET" not in os.environ:
    raise RuntimeError("FLASK_SECRET must be set.")
app.secret_key = os.environ["FLASK_SECRET"]
ph = PasswordHasher()

if "JWT_SECRET" not in os.environ:
    raise RuntimeError("JWT_SECRET must be set.")
JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALG = "HS256"
JWT_EXP_MINUTES = 30
REFRESH_EXP_DAYS = 7
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL must point to your Cloud SQL/Postgres instance.")
engine: Engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=int(os.environ.get("DB_POOL_SIZE", "5")),
    max_overflow=int(os.environ.get("DB_MAX_OVERFLOW", "10")),
    future=True,
)

# Rate limiting
RATE_WINDOW_SEC = 60
RATE_MAX_FAILS = 5
LOCKOUT_SEC = 300
_failed_logins: dict[str, list[float]] = {}
_lockouts: dict[str, float] = {}

CSRF_COOKIE_NAME = "csrf_token"
ACCESS_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"

# Creates database if doesn't exist
def init_db() -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    vault_salt BYTEA
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS vault_items (
                    user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                    vault_ciphertext TEXT,
                    nonce TEXT,
                    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
                );
                """
            )
        )
        conn.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    token_hash TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    expires_at TIMESTAMPTZ NOT NULL
                );
                """
            )
        )
@app.before_request
def _handle_options_request():
    if request.method == "OPTIONS":
        return make_response("", 204)


@app.after_request
def _add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = os.environ.get("CORS_ALLOW_ORIGIN", "*")
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization, X-CSRF-Token"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return response


# Creates JWT for authenticated users
def create_token(user_id: int, username: str) -> str:
    payload = {
        "sub": username,
        "uid": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

# Creates refresh token to issue new access tokens upon expiry
def create_refresh_token(user_id: int, username: str) -> str:
    payload = {
        "sub": username,
        "uid": user_id,
        "typ": "refresh",
        "exp": datetime.utcnow() + timedelta(days=REFRESH_EXP_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def _issue_tokens(user_id: int, username: str) -> tuple[str, str]:
    access = create_token(user_id, username)
    refresh = create_refresh_token(user_id, username)
    _store_refresh_token(user_id, refresh)
    return access, refresh

# Refresh token helpers
def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _store_refresh_token(user_id: int, token: str) -> None:
    token_hash = _hash_refresh_token(token)
    expires_at = (datetime.utcnow() + timedelta(days=REFRESH_EXP_DAYS)).isoformat()
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO refresh_tokens (token_hash, user_id, expires_at)
                VALUES (:token_hash, :user_id, :expires_at)
                ON CONFLICT (token_hash) DO UPDATE SET
                    user_id = EXCLUDED.user_id,
                    expires_at = EXCLUDED.expires_at
                """
            ),
            {"token_hash": token_hash, "user_id": user_id, "expires_at": expires_at},
        )


def _verify_refresh_token(user_id: int, token: str) -> bool:
    token_hash = _hash_refresh_token(token)
    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT user_id, expires_at FROM refresh_tokens WHERE token_hash = :token_hash"),
            {"token_hash": token_hash},
        ).fetchone()
    if not row:
        return False
    stored_user_id, expires_at = row
    if stored_user_id != user_id:
        _revoke_refresh_token(token)
        return False
    try:
        if datetime.utcnow() >= datetime.fromisoformat(expires_at):
            _revoke_refresh_token(token)
            return False
    except ValueError:
        _revoke_refresh_token(token)
        return False
    return True


def _revoke_refresh_token(token: str) -> None:
    token_hash = _hash_refresh_token(token)
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM refresh_tokens WHERE token_hash = :token_hash"),
            {"token_hash": token_hash},
        )


def _clear_refresh_tokens_for_user(user_id: int) -> None:
    with engine.begin() as conn:
        conn.execute(
            text("DELETE FROM refresh_tokens WHERE user_id = :user_id"),
            {"user_id": user_id},
        )


def _get_vault_salt(user_id: int) -> bytes:
    with engine.begin() as conn:
        row = conn.execute(
            text("SELECT vault_salt FROM users WHERE id = :user_id"),
            {"user_id": user_id},
        ).fetchone()
        if not row:
            raise ValueError("User not found.")
        existing = row[0]
        if existing:
            return bytes(existing)
        salt = os.urandom(16)
        conn.execute(
            text("UPDATE users SET vault_salt = :salt WHERE id = :user_id"),
            {"salt": salt, "user_id": user_id},
        )
        return salt


def _normalize_blob_value(value: bytes | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value.decode("utf-8")
    return value


def _uses_bearer_auth() -> bool:
    auth_header = request.headers.get("Authorization", "")
    return auth_header.startswith("Bearer ")


def _get_authenticated_user() -> tuple[int | None, str | None]:
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if not token:
            return None, None
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        except InvalidTokenError:
            return None, None
        return payload.get("uid"), payload.get("sub")
    return get_current_user()

# Get CSRF cookie and if it doesn't exist set it then get it
def _get_or_set_csrf_cookie(response=None) -> str:
    token = request.cookies.get(CSRF_COOKIE_NAME)
    if token:
        return token

    token = secrets.token_urlsafe(32)
    if response is not None:
        response.set_cookie(
            CSRF_COOKIE_NAME,
            token,
            httponly=False,
            samesite="Lax",
            secure=COOKIE_SECURE,
        )
    return token

# Verify CSRF cookie
def _verify_csrf() -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    form_token = request.form.get("csrf_token", "")
    return bool(cookie_token) and cookie_token == form_token

def _verify_csrf_header() -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    header_token = request.headers.get("X-CSRF-Token", "")
    return bool(cookie_token) and cookie_token == header_token



# Render a page and embed the csrf in form data and cookie
def _render_with_csrf(template_name: str, **context):
    response = make_response(
        render_template(template_name, csrf_token=_get_or_set_csrf_cookie(), **context)
    )
    _get_or_set_csrf_cookie(response)
    return response

# Get the current user from the access token
def get_current_user() -> tuple[int | None, str | None]:
    token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not token:
        return None, None

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except InvalidTokenError:
        return None, None
    return payload.get("uid"), payload.get("sub")

# Loads the encypted vault passwords, decrypts them, returns them
def _get_vault_payload(user_id: int) -> tuple[str | None, str | None]:
    with engine.connect() as conn:
        row = conn.execute(
            text(
                "SELECT vault_ciphertext, nonce FROM vault_items WHERE user_id = :user_id"
            ),
            {"user_id": user_id},
        ).fetchone()

    if not row:
        return None, None

    ciphertext = _normalize_blob_value(row[0])
    nonce = _normalize_blob_value(row[1])
    return ciphertext, nonce

# Gets the encrypted vault payload, saves it
def _save_vault_payload(user_id: int, ciphertext: str, nonce: str) -> None:
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                INSERT INTO vault_items (user_id, vault_ciphertext, nonce, updated_at)
                VALUES (:user_id, :ciphertext, :nonce, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    vault_ciphertext = EXCLUDED.vault_ciphertext,
                    nonce = EXCLUDED.nonce,
                    updated_at = CURRENT_TIMESTAMP
                """
            ),
            {"user_id": user_id, "ciphertext": ciphertext, "nonce": nonce},
        )


# Checks if user is logged in or else displays login page
@app.route("/")
def index():
    user_id, _ = get_current_user()
    if user_id:
        return redirect(url_for("protected"))
    return redirect(url_for("login"))

# Register Page
@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        if not _verify_csrf():
            return "CSRF token missing or invalid", 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            error = "Username and password are required."
            return _render_with_csrf("register.html", error=error), 400
        
        # Hashes password using Argon2
        password_hash = ph.hash(password)
        try:
            with engine.begin() as conn:
                result = conn.execute(
                    text(
                        "INSERT INTO users (username, password) VALUES (:username, :password) RETURNING id"
                    ),
                    {"username": username, "password": password_hash},
                )
                user_id = result.scalar_one()
        except IntegrityError:
            error = "That username is already taken."
            return _render_with_csrf("register.html", error=error), 400

        _get_vault_salt(user_id)

        return redirect(url_for("login"))

    return _render_with_csrf("register.html", error=error)

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if not _verify_csrf():
            return "CSRF token missing or invalid", 400

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
        rate_key = f"{username.lower()}|{client_ip}"
        now = time.monotonic()

        locked_until = _lockouts.get(rate_key)
        if locked_until and now < locked_until:
            error = "Too many failed attempts. Try again later."
            return _render_with_csrf("login.html", error=error), 429

        # Checks if username exists
        with engine.connect() as conn:
            row = conn.execute(
                text("SELECT id, password FROM users WHERE username = :username"),
                {"username": username},
            ).fetchone()
        # If doesn't exist throw error
        if not row:
            error = "Invalid credentials"
        # If exists verify password
        else:
            stored = row[1]
            ok = False
            try:
                # Hash users password and compare to stored hash
                ok = ph.verify(stored, password)
            except VerifyMismatchError:
                ok = False

            # Hashes don't match
            if not ok:
                attempts = _failed_logins.get(rate_key, [])
                attempts = [ts for ts in attempts if now - ts <= RATE_WINDOW_SEC]
                attempts.append(now)
                _failed_logins[rate_key] = attempts
                if len(attempts) >= RATE_MAX_FAILS:
                    _lockouts[rate_key] = now + LOCKOUT_SEC
                    error = "Too many failed attempts. Try again later."
                    return _render_with_csrf("login.html", error=error), 429
                error = "Invalid credentials"
            # Hashes match
            else:
                _failed_logins.pop(rate_key, None)
                _lockouts.pop(rate_key, None)
                # Create JWT
                token = create_token(row[0], username)
                refresh_token = create_refresh_token(row[0], username)
                _store_refresh_token(row[0], refresh_token)
                response = redirect(url_for("protected"))
                response.set_cookie(
                    ACCESS_COOKIE_NAME,
                    token,
                    httponly=True,
                    samesite="Lax",
                    secure=COOKIE_SECURE,
                )
                response.set_cookie(
                    REFRESH_COOKIE_NAME,
                    refresh_token,
                    httponly=True,
                    samesite="Lax",
                    secure=COOKIE_SECURE,
                )
                return response

    return _render_with_csrf("login.html", error=error)

@app.route("/api/auth/register", methods=["POST"])
def api_auth_register():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400
    password_hash = ph.hash(password)
    try:
        with engine.begin() as conn:
            result = conn.execute(
                text(
                    "INSERT INTO users (username, password) VALUES (:username, :password) RETURNING id"
                ),
                {"username": username, "password": password_hash},
            )
            user_id = result.scalar_one()
    except IntegrityError:
        return jsonify({"error": "Username already exists."}), 409

    access, refresh = _issue_tokens(user_id, username)
    salt_b64 = base64.b64encode(_get_vault_salt(user_id)).decode("utf-8")
    return (
        jsonify(
            {
                "access_token": access,
                "refresh_token": refresh,
                "vault_salt": salt_b64,
                "username": username,
            }
        ),
        201,
    )


@app.route("/api/auth/login", methods=["POST"])
def api_auth_login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "").strip()
    password = data.get("password", "")
    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT id, password FROM users WHERE username = :username"),
            {"username": username},
        ).fetchone()

    if not row:
        return jsonify({"error": "Invalid credentials."}), 401

    try:
        ph.verify(row[1], password)
    except VerifyMismatchError:
        return jsonify({"error": "Invalid credentials."}), 401

    access, refresh = _issue_tokens(row[0], username)
    salt_b64 = base64.b64encode(_get_vault_salt(row[0])).decode("utf-8")
    return jsonify(
        {
            "access_token": access,
            "refresh_token": refresh,
            "vault_salt": salt_b64,
            "username": username,
        }
    )


@app.route("/api/auth/refresh", methods=["POST"])
def api_auth_refresh():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")
    if not refresh_token:
        return jsonify({"error": "Refresh token is required."}), 400

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALG])
    except InvalidTokenError:
        return jsonify({"error": "Invalid refresh token."}), 401

    if payload.get("typ") != "refresh":
        return jsonify({"error": "Invalid refresh token."}), 401

    user_id = payload.get("uid")
    username = payload.get("sub")
    if not user_id or not username:
        return jsonify({"error": "Invalid refresh token."}), 401

    if not _verify_refresh_token(user_id, refresh_token):
        _revoke_refresh_token(refresh_token)
        return jsonify({"error": "Invalid refresh token."}), 401

    access, new_refresh = _issue_tokens(user_id, username)
    return jsonify({"access_token": access, "refresh_token": new_refresh})


@app.route("/api/auth/logout", methods=["POST"])
def api_auth_logout():
    data = request.get_json(silent=True) or {}
    refresh_token = data.get("refresh_token", "")
    if not refresh_token:
        return jsonify({"error": "Refresh token is required."}), 400

    try:
        payload = jwt.decode(refresh_token, JWT_SECRET, algorithms=[JWT_ALG])
    except InvalidTokenError:
        return jsonify({"error": "Invalid refresh token."}), 401

    user_id_from_token = payload.get("uid")
    if not user_id_from_token:
        return jsonify({"error": "Invalid refresh token."}), 401

    _revoke_refresh_token(refresh_token)
    return jsonify({"ok": True})


# Verifying the users password when setting vault password
@app.route("/api/verify-login", methods=["POST"])
def api_verify_login():
    if not _uses_bearer_auth() and not _verify_csrf_header():
        return jsonify({"error": "CSRF token missing or invalid"}), 400

    user_id, _ = _get_authenticated_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    if not isinstance(password, str) or not password:
        return jsonify({"error": "Password is required"}), 400

    with engine.connect() as conn:
        row = conn.execute(
            text("SELECT password FROM users WHERE id = :user_id"),
            {"user_id": user_id},
        ).fetchone()

    if not row:
        return jsonify({"error": "Unauthorized"}), 401

    try:
        ph.verify(row[0], password)
    except VerifyMismatchError:
        return jsonify({"ok": False}), 401

    return jsonify({"ok": True}), 200

# Logged in page
@app.route("/protected", methods=["GET"])
def protected():
    user_id, username = get_current_user()
    if not user_id:
        return redirect(url_for("login"))

    vault_salt = _get_vault_salt(user_id)
    return _render_with_csrf(
        "vault.html",
        username=username,
        vault_salt=base64.b64encode(vault_salt).decode("utf-8"),
    )

@app.route("/api/vault", methods=["GET"])
def api_vault_get():
    user_id, _ = _get_authenticated_user()
    if not user_id:
        return jsonify({"error": "Unauthorized"}), 401

    ciphertext, nonce = _get_vault_payload(user_id)
    salt_b64 = base64.b64encode(_get_vault_salt(user_id)).decode("utf-8")
    return jsonify({"ciphertext": ciphertext, "nonce": nonce, "vault_salt": salt_b64}), 200


@app.route("/api/vault", methods=["POST"])
def api_vault_post():
    if not _uses_bearer_auth() and not _verify_csrf_header():
        return "CSRF token missing or invalid", 400

    user_id, _ = _get_authenticated_user()
    if not user_id:
        return "Unauthorized", 401

    data = request.get_json(silent=True) or {}
    ciphertext = data.get("ciphertext")
    nonce = data.get("nonce")
    if not isinstance(ciphertext, str) or not isinstance(nonce, str):
        return "Invalid vault payload", 400

    _save_vault_payload(user_id, ciphertext, nonce)
    return jsonify({"ok": True}), 200


@app.route("/api/csrf", methods=["GET"])
def api_csrf():
    response = jsonify({"csrf_token": _get_or_set_csrf_cookie()})
    _get_or_set_csrf_cookie(response)
    response.headers["Cache-Control"] = "no-store"
    return response

# Logout
@app.route("/logout")
def logout():
    user_id, _ = get_current_user()
    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if token:
        _revoke_refresh_token(token)
    elif user_id:
        _clear_refresh_tokens_for_user(user_id)
    response = redirect(url_for("login"))
    response.delete_cookie(ACCESS_COOKIE_NAME)
    response.delete_cookie(REFRESH_COOKIE_NAME)
    return response

# Refresh Token
@app.route("/refresh", methods=["POST"])
def refresh():
    if not _verify_csrf():
        return "CSRF token missing or invalid", 400

    token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not token:
        return "Missing refresh token", 401

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except InvalidTokenError:
        return "Invalid refresh token", 401

    if payload.get("typ") != "refresh":
        return "Invalid refresh token", 401

    user_id = payload.get("uid")
    username = payload.get("sub")
    if not user_id or not username:
        return "Invalid refresh token", 401

    if not _verify_refresh_token(user_id, token):
        _revoke_refresh_token(token)
        return "Invalid refresh token", 401

    new_access, new_refresh = _issue_tokens(user_id, username)
    response = redirect(url_for("protected"))
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        new_access,
        httponly=True,
        samesite="Lax",
        secure=COOKIE_SECURE,
    )
    response.set_cookie(
        REFRESH_COOKIE_NAME,
        new_refresh,
        httponly=True,
        samesite="Lax",
        secure=COOKIE_SECURE,
    )
    return response

# init_db()

if __name__ == "__main__":
    app.run(debug=True)
