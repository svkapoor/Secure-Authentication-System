from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

import jwt
from flask import Flask, make_response, redirect, render_template, request, url_for
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from argon2.low_level import Type as Argon2Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from jwt import InvalidTokenError

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "app.db"

app = Flask(
    __name__,
    template_folder=str(APP_DIR / "templates"),
    static_folder=str(APP_DIR / "static"),
)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")
ph = PasswordHasher()

JWT_SECRET = os.environ.get("JWT_SECRET", app.secret_key)
JWT_ALG = "HS256"
JWT_EXP_MINUTES = 30
REFRESH_EXP_DAYS = 7
COOKIE_SECURE = os.environ.get("COOKIE_SECURE", "0") == "1"

# Rate limiting
RATE_WINDOW_SEC = 60
RATE_MAX_FAILS = 5
LOCKOUT_SEC = 300
VAULT_UNLOCK_SEC = 300
_failed_logins: dict[str, list[float]] = {}
_lockouts: dict[str, float] = {}
_vault_unlocks: dict[int, tuple[bytes, float]] = {}

CSRF_COOKIE_NAME = "csrf_token"
ACCESS_COOKIE_NAME = "access_token"
REFRESH_COOKIE_NAME = "refresh_token"

# Creates database if doesn't exist
def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                vault_salt BLOB
            );
            """
        )
        user_columns = conn.execute("PRAGMA table_info(users)").fetchall()
        if not any(col[1] == "vault_salt" for col in user_columns):
            conn.execute("ALTER TABLE users ADD COLUMN vault_salt BLOB")
        info = conn.execute("PRAGMA table_info(vault_items)").fetchall()
        if info and not any(col[1] == "vault_ciphertext" for col in info):
            conn.execute("DROP TABLE vault_items")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_items (
                user_id INTEGER PRIMARY KEY,
                vault_ciphertext BLOB NOT NULL,
                nonce BLOB NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                user_id INTEGER PRIMARY KEY,
                token_hash TEXT NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            """
        )
@app.before_request
def _ensure_db() -> None:
    init_db()


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

# Refresh token helpers
def _hash_refresh_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _store_refresh_token(user_id: int, token: str) -> None:
    token_hash = _hash_refresh_token(token)
    expires_at = (datetime.utcnow() + timedelta(days=REFRESH_EXP_DAYS)).isoformat()
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                token_hash=excluded.token_hash,
                expires_at=excluded.expires_at
            """,
            (user_id, token_hash, expires_at),
        )


def _verify_refresh_token(user_id: int, token: str) -> bool:
    token_hash = _hash_refresh_token(token)
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT token_hash, expires_at FROM refresh_tokens WHERE user_id = ?",
            (user_id,),
        ).fetchone()
    if not row:
        return False
    stored_hash, expires_at = row
    if stored_hash != token_hash:
        return False
    try:
        if datetime.utcnow() >= datetime.fromisoformat(expires_at):
            _clear_refresh_token(user_id)
            return False
    except ValueError:
        _clear_refresh_token(user_id)
        return False
    return True


def _clear_refresh_token(user_id: int) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("DELETE FROM refresh_tokens WHERE user_id = ?", (user_id,))


def _get_vault_salt(user_id: int) -> bytes:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT vault_salt FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not row:
            raise ValueError("User not found.")
        existing = row[0]
        if existing:
            return bytes(existing)
        salt = os.urandom(16)
        conn.execute(
            "UPDATE users SET vault_salt = ? WHERE id = ?",
            (salt, user_id),
        )
        return salt

# Uses the master password and salt to create a vault key
def _derive_vault_key(passphrase: str, user_id: int) -> bytes:
    if not passphrase:
        raise ValueError("Vault passphrase required.")
    salt = _get_vault_salt(user_id)
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"), # master password as bytes
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Argon2Type.ID,
    )

# Encrypts saved passwords
def encrypt_secret(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    aes = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aes.encrypt(nonce, plaintext.encode("utf-8"), None)
    return nonce, ciphertext

# Descrypts saved passwords
def decrypt_secret(nonce: bytes, ciphertext: bytes, key: bytes) -> str:
    aes = AESGCM(key)
    return aes.decrypt(nonce, ciphertext, None).decode("utf-8")

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

# Vault unlocking has begun for 5 minutes
def _set_vault_unlock(user_id: int, key: bytes) -> None:
    _vault_unlocks[user_id] = (key, time.monotonic() + VAULT_UNLOCK_SEC)

# Checks if vault is still unlocked
def _get_vault_unlock(user_id: int) -> tuple[bytes | None, int]:
    entry = _vault_unlocks.get(user_id)
    if not entry:
        return None, 0
    key, expires_at = entry
    now = time.monotonic()
    if now >= expires_at:
        _vault_unlocks.pop(user_id, None)
        return None, 0
    remaining = int(expires_at - now)
    return key, remaining



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
def _load_vault_entries(user_id: int, key: bytes) -> list[dict[str, str]]:
    with sqlite3.connect(DB_PATH) as conn:
        row = conn.execute(
            "SELECT vault_ciphertext, nonce FROM vault_items WHERE user_id = ?",
            (user_id,),
        ).fetchone()

    if not row:
        return []

    try:
        plaintext = decrypt_secret(row[1], row[0], key)
        data = json.loads(plaintext)
    except Exception as exc:
        raise ValueError("Unable to decrypt vault with provided passphrase.") from exc

    if isinstance(data, list):
        return data
    return []

# Gets the passwords, encrypts them, saves them
def _save_vault_entries(user_id: int, entries: list[dict[str, str]], key: bytes) -> None:
    payload = json.dumps(entries)
    nonce, ciphertext = encrypt_secret(payload, key)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """
            INSERT INTO vault_items (user_id, vault_ciphertext, nonce, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                vault_ciphertext=excluded.vault_ciphertext,
                nonce=excluded.nonce,
                updated_at=CURRENT_TIMESTAMP
            """,
            (user_id, ciphertext, nonce),
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
        with sqlite3.connect(DB_PATH) as conn:
            try:
                cursor = conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password_hash),
                )
            except sqlite3.IntegrityError:
                error = "That username is already taken."
                return _render_with_csrf("register.html", error=error), 400
            user_id = cursor.lastrowid

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
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT id, password FROM users WHERE username = ?",
                (username,),
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

# Logged in page
@app.route("/protected", methods=["GET", "POST"])
def protected():
    # Verify token
    user_id, username = get_current_user()
    if not user_id:
        return redirect(url_for("login"))

    error = None
    vault_entries: list[dict[str, str]] | None = None
    cached_key, unlock_remaining = _get_vault_unlock(user_id)

    if request.method == "POST":
        if not _verify_csrf():
            return "CSRF token missing or invalid", 400

        action = request.form.get("action", "unlock")
        passphrase = request.form.get("vault_passphrase", "")
        key = None

        if passphrase:
            try:
                key = _derive_vault_key(passphrase, user_id)
            except ValueError as exc:
                error = str(exc)
        elif cached_key:
            key = cached_key
        else:
            error = "Vault passphrase is required."

        if key and not error:
            if action == "add":
                label = request.form.get("label", "").strip()
                vault_username = request.form.get("vault_username", "").strip()
                vault_password = request.form.get("vault_password", "")
                if not label or not vault_username or not vault_password:
                    error = "All fields are required to store a password."
                else:
                    try:
                        current_entries = _load_vault_entries(user_id, key)
                    except ValueError:
                        error = "Incorrect vault passphrase."
                    else:
                        entry = {
                            "label": label,
                            "login_name": vault_username,
                            "password": vault_password,
                            "created_at": datetime.utcnow().isoformat(),
                        }
                        updated_entries = [entry] + current_entries
                        try:
                            _save_vault_entries(user_id, updated_entries, key)
                        except Exception:
                            error = "Unable to encrypt vault. Please try again."
                        else:
                            vault_entries = updated_entries
                            if passphrase:
                                _set_vault_unlock(user_id, key)
                                cached_key = key
                                unlock_remaining = VAULT_UNLOCK_SEC
            else:
                try:
                    vault_entries = _load_vault_entries(user_id, key)
                except ValueError:
                    error = "Incorrect vault passphrase or vault data is corrupted."
                else:
                    if passphrase:
                        _set_vault_unlock(user_id, key)
                        cached_key = key
                        unlock_remaining = VAULT_UNLOCK_SEC
    elif cached_key:
        try:
            vault_entries = _load_vault_entries(user_id, cached_key)
        except ValueError:
            error = "Unable to decrypt vault with the cached unlock."
            _vault_unlocks.pop(user_id, None)
            cached_key = None
            unlock_remaining = 0

    return _render_with_csrf(
        "vault.html",
        username=username,
        vault_entries=vault_entries,
        error=error,
        vault_unlocked=bool(cached_key),
        vault_unlock_remaining=unlock_remaining,
    )

# Logout
@app.route("/logout")
def logout():
    user_id, _ = get_current_user()
    if user_id:
        _vault_unlocks.pop(user_id, None)
        _clear_refresh_token(user_id)
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
        _clear_refresh_token(user_id)
        return "Invalid refresh token", 401

    new_access = create_token(user_id, username)
    new_refresh = create_refresh_token(user_id, username)
    _store_refresh_token(user_id, new_refresh)
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


if __name__ == "__main__":
    app.run(debug=True)
