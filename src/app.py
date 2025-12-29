from __future__ import annotations

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
_failed_logins: dict[str, list[float]] = {}
_lockouts: dict[str, float] = {}

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
                password TEXT NOT NULL
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


def create_refresh_token(user_id: int, username: str) -> str:
    payload = {
        "sub": username,
        "uid": user_id,
        "typ": "refresh",
        "exp": datetime.utcnow() + timedelta(days=REFRESH_EXP_DAYS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


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


def _verify_csrf() -> bool:
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
    form_token = request.form.get("csrf_token", "")
    return bool(cookie_token) and cookie_token == form_token


def _render_with_csrf(template_name: str, **context):
    response = make_response(
        render_template(template_name, csrf_token=_get_or_set_csrf_cookie(), **context)
    )
    _get_or_set_csrf_cookie(response)
    return response


def get_current_user() -> tuple[int | None, str | None]:
    token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not token:
        return None, None

    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except InvalidTokenError:
        return None, None

    return payload.get("uid"), payload.get("sub")

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
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password_hash),
                )
            except sqlite3.IntegrityError:
                error = "That username is already taken."
                return _render_with_csrf("register.html", error=error), 400

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


@app.route("/protected")
def protected():
    # Verify token
    user_id, username = get_current_user()
    if not user_id:
        return redirect(url_for("login"))
    return _render_with_csrf("protected.html", username=username)


@app.route("/logout")
def logout():
    response = redirect(url_for("login"))
    response.delete_cookie(ACCESS_COOKIE_NAME)
    response.delete_cookie(REFRESH_COOKIE_NAME)
    return response


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

    new_access = create_token(user_id, username)
    response = redirect(url_for("protected"))
    response.set_cookie(
        ACCESS_COOKIE_NAME,
        new_access,
        httponly=True,
        samesite="Lax",
        secure=COOKIE_SECURE,
    )
    return response


if __name__ == "__main__":
    app.run(debug=True)
