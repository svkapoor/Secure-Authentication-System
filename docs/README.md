# Secure Authentication System

This project is a learning-focused authentication app. It starts simple and incrementally adds defenses so you can see what each security control does and why it matters.

## Features implemented
- Argon2id password hashing for stored credentials.
- JWT-based authentication with HttpOnly cookies.
- Access + refresh token flow (`/refresh` issues a new access token).
- CSRF protection for POST requests (double-submit cookie).
- Login rate limiting + temporary lockout per username/IP.
- Basic protected route with JWT verification.

## Quick start (Windows)
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
set JWT_SECRET=replace-with-a-strong-secret
python src\app.py
```

Open `http://127.0.0.1:5000/`.

## Configuration
Environment variables:
- `JWT_SECRET` (required for real use): strong random secret for signing tokens.
- `COOKIE_SECURE` (optional): set to `1` when running over HTTPS to mark cookies as `Secure`.
- `FLASK_SECRET` (optional): Flask secret key; defaults to `dev-secret`.

## How authentication works
1) Register creates an Argon2id hash and stores it in SQLite (`src/app.db`).
2) Login verifies the password, then issues:
   - `access_token`: short-lived JWT (30 minutes).
   - `refresh_token`: long-lived JWT (7 days).
3) Protected routes read and verify the `access_token`.
4) `/refresh` (POST) validates the refresh token and issues a new access token.

## CSRF protection
POST requests require a CSRF token:
- A `csrf_token` cookie is set.
- Forms include a hidden `csrf_token` field.
- The server verifies the cookie and form values match.

This protects cookie-based JWT auth from cross-site request forgery.

## Rate limiting and lockout
Login attempts are limited per username + IP:
- Window: 60 seconds.
- Max failures: 5.
- Lockout: 5 minutes.

Note: counters are in-memory and reset on app restart.

## Endpoints
- `GET /` redirects to login or protected page.
- `GET/POST /register`
- `GET/POST /login`
- `GET /protected`
- `POST /refresh`
- `GET /logout`

## Project structure
- `src/app.py`: Flask app and auth logic.
- `docs/README.md`: project overview and usage.
- `tests/`: reserved for tests.
- `scripts/`: reserved for helper scripts.

## Learning goals
- Compare plaintext vs hashed passwords.
- Understand JWT structure, expiry, and verification.
- Learn CSRF risks with cookie-based auth and how to mitigate them.
- See how rate limiting slows brute-force attempts.

## Known limitations (for learning)
- Refresh tokens are not stored or revoked server-side.
- Rate limiting is in-memory and not shared across instances.
- No MFA, password reset, or breached password checks.
- Templates are inline (no CSP or XSS hardening).

## Suggested next steps
- Store refresh tokens in SQLite and rotate/revoke on use.
- Add audit logging for auth events.
- Enforce stronger password policy.
- Add MFA (TOTP).
- Move templates to separate files and add CSP headers.
