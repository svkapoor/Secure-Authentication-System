from __future__ import annotations

import os
import sqlite3
from pathlib import Path

from flask import Flask, redirect, render_template_string, request, session, url_for
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

APP_DIR = Path(__file__).resolve().parent
DB_PATH = APP_DIR / "app.db"

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")
ph = PasswordHasher()


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
<p style="color: #a00">This version stores plaintext passwords for learning purposes only.</p>
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


@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("protected"))
    return redirect(url_for("login"))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or not password:
            return render_template_string(REGISTER_TEMPLATE), 400

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


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute(
                "SELECT id, password FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if not row:
            error = "Invalid credentials"
        else:
            stored = row[1]
            ok = False
            if stored.startswith("$argon2id$"):
                try:
                    ok = ph.verify(stored, password)
                except VerifyMismatchError:
                    ok = False
            else:
                ok = stored == password
                if ok:
                    new_hash = ph.hash(password)
                    with sqlite3.connect(DB_PATH) as update_conn:
                        update_conn.execute(
                            "UPDATE users SET password = ? WHERE id = ?",
                            (new_hash, row[0]),
                        )

            if not ok:
                error = "Invalid credentials"
            else:
                session["user_id"] = row[0]
                session["username"] = username
                return redirect(url_for("protected"))

    return render_template_string(LOGIN_TEMPLATE, error=error)


@app.route("/protected")
def protected():
    if not session.get("user_id"):
        return redirect(url_for("login"))
    return render_template_string(PROTECTED_TEMPLATE, username=session.get("username"))


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
