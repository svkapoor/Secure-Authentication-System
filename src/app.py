from __future__ import annotations

import os
import sqlite3
import time
from datetime import datetime, timedelta
from pathlib import Path

import jwt
from flask import Flask, redirect, render_template_string, request, url_for
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from jwt import InvalidTokenError

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "app.db"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")
ph = PasswordHasher()

JWT_SECRET = os.environ.get("JWT_SECRET", app.secret_key)
JWT_ALG = "HS256"
JWT_EXP_MINUTES = 30

RATE_WINDOW_SEC = 60
RATE_MAX_FAILS = 5
LOCKOUT_SEC = 300
_failed_logins: dict[str, list[float]] = {}
_lockouts: dict[str, float] = {}

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


REGISTER_TEMPLATE = """
<!doctype html>
<title>Register</title>
<h1>Register</h1>
<form method="post">
  <label>Username <input name="username" required></label><br>
  <label>Password <input name="password" type="password" required></label><br>
  <button type="submit">Create account</button>
</form>
<p><a href="{{ url_for('login') }}">Login</a></p>
"""

LOGIN_TEMPLATE = """
<!doctype html>
<title>Login</title>
<h1>Login</h1>
<form method="post">
  <label>Username <input name="username" required></label><br>
  <label>Password <input name="password" type="password" required></label><br>
  <button type="submit">Sign in</button>
</form>
<p><a href="{{ url_for('register') }}">Register</a></p>
{% if error %}<p style="color: #a00">{{ error }}</p>{% endif %}
"""

PROTECTED_TEMPLATE = """
<!doctype html>
<title>Protected</title>
<h1>Welcome, {{ username }}!</h1>
<p>This is a protected page.</p>
<p><a href="{{ url_for('logout') }}">Logout</a></p>
"""

# Creates JWT for authenticated users
def create_token(user_id: int, username: str) -> str:
    payload = {
        "sub": username,
        "uid": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXP_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


def get_current_user() -> tuple[int | None, str | None]:
    token = request.cookies.get("access_token")
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
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            return render_template_string(REGISTER_TEMPLATE), 400
        
        # Hashes password using Argon2
        password_hash = ph.hash(password)
        with sqlite3.connect(DB_PATH) as conn:
            try:
                conn.execute(
                    "INSERT INTO users (username, password) VALUES (?, ?)",
                    (username, password_hash),
                )
            except sqlite3.IntegrityError:
                return render_template_string(REGISTER_TEMPLATE), 400

        return redirect(url_for("login"))

    return render_template_string(REGISTER_TEMPLATE)

# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
        rate_key = f"{username.lower()}|{client_ip}"
        now = time.monotonic()

        locked_until = _lockouts.get(rate_key)
        if locked_until and now < locked_until:
            error = "Too many failed attempts. Try again later."
            return render_template_string(LOGIN_TEMPLATE, error=error), 429

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
                    return render_template_string(LOGIN_TEMPLATE, error=error), 429
                error = "Invalid credentials"
            # Hashes match
            else:
                _failed_logins.pop(rate_key, None)
                _lockouts.pop(rate_key, None)
                # Create JWT
                token = create_token(row[0], username)
                response = redirect(url_for("protected"))
                response.set_cookie(
                    "access_token",
                    token,
                    httponly=True,
                    samesite="Lax",
                )
                return response

    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route("/protected")
def protected():
    # Verify token
    user_id, username = get_current_user()
    if not user_id:
        return redirect(url_for("login"))
    return render_template_string(PROTECTED_TEMPLATE, username=username)


@app.route("/logout")
def logout():
    response = redirect(url_for("login"))
    response.delete_cookie("access_token")
    return response


if __name__ == "__main__":
    app.run(debug=True)
