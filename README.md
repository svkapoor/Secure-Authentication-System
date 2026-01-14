# Secure Authentication System & Zero-Knowledge Vault

A Flask application that demonstrates modern authentication patterns (Argon2 password hashing, JWT access/refresh tokens, CSRF defenses, adaptive rate limiting) paired with a zero-knowledge password manager. Users authenticate with traditional credentials, then unlock an encrypted vault whose contents are encrypted/decrypted entirely in the browser via Web Crypto (PBKDF2 + AES-256-GCM). The server only ever stores ciphertext and per-user salts.

## Features & Security Highlights
- **Argon2 password hashing** for account credentials via `argon2-cffi`.
- **Adaptive rate limiting & lockouts** keyed by username/IP to throttle brute-force login attempts.
- **JWT access tokens + hashed refresh tokens** stored in HTTP-only cookies, with refresh token material hashed in the database and revocation support.
- **Mandatory environment secrets** (`FLASK_SECRET`, `JWT_SECRET`) so cryptographic keys are never hard-coded.
- **CSRF protection** using a double-submit cookie for HTML forms and `X-CSRF-Token` headers for JSON APIs.
- **Zero-knowledge vault encryption**:
  - Each user receives a random 16-byte salt stored alongside their account.
  - Vault passphrases stay client-side; PBKDF2 (200k iterations, SHA-256) derives a 256-bit AES-GCM key in the browser.
  - Ciphertext + nonce are the only vault artifacts persisted to SQLite.
  - Vault auto-locks after five minutes of inactivity and wipes the derived key from memory.
  - First-time vault setup re-verifies the user’s login password (via `/api/verify-login`) before accepting a passphrase and enforces “passphrase ≠ login password”.
- **Per-request CSRF + refresh token verification endpoints** to keep API interactions safe.
- **Client UX niceties:** inline errors, unlock countdown, table rendering for saved credentials, and progressive disclosure of setup vs. unlock states.

## Prerequisites
- Python 3.11+ (recommended)
- `pip` / `venv`
- Recent browser with Web Crypto API (Edge/Chrome/Firefox/Safari modern versions)

## Installation
```bash
git clone https://github.com/your-user/Secure-Authentication-System.git
cd Secure-Authentication-System
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install --upgrade pip
pip install -r requirements.txt
```

## Environment Configuration
Create a `.env` file or export variables in your shell before running the app.

| Variable | Required | Description |
| --- | --- | --- |
| `FLASK_SECRET` | ✅ | 32+ character secret string used for Flask session key derivation, CSRF token signing, and default entropy for salts. |
| `JWT_SECRET` | ✅ | Secret string used to sign/verify JWT access and refresh tokens. Keep it distinct from `FLASK_SECRET`. |
| `COOKIE_SECURE` | optional | Set to `1` in production to mark cookies as `Secure` so they are only sent over HTTPS. |
| `CORS_ALLOW_ORIGIN` | optional | Value for the `Access-Control-Allow-Origin` header on API responses (defaults to `*`). Set to your production origin(s) when deploying the extension. |

Example (macOS/Linux):
```bash
export FLASK_SECRET="change-me-super-long-secret"
export JWT_SECRET="another-long-secret"
export COOKIE_SECURE=0  # enable (1) when serving over HTTPS
```

## Running the App
```bash
source .venv/bin/activate
python src/app.py
```
The server listens on `http://127.0.0.1:5000` by default (Flask debug mode is enabled for local development).

## Using the Application
1. **Register** a new account (username + password). Passwords are hashed with Argon2 before touching the database.
2. **Log in**. Rate limiting guards against repeated failures and lockouts expire automatically.
3. **Set a vault passphrase** the first time you open the dashboard:
   - Re-enter your login password; it’s verified via `/api/verify-login` to ensure you’re the rightful owner.
   - Choose a unique vault passphrase. Client-side checks ensure it differs from the login password and that you confirm it.
   - The browser derives a 256-bit key with PBKDF2 + your per-user salt and encrypts an empty vault; the server stores only ciphertext/nonce.
4. **Unlock the vault** on subsequent visits by entering the passphrase. The key lives in memory for five minutes, after which the vault auto-locks and the key is cleared.
5. **Add credentials**. Each entry stays entirely client-side until it’s encrypted; decrypted secrets never hit the network or the database in plaintext.
6. **Refresh tokens** silently extend your session via `/refresh`, while `/logout` clears both HTTP-only cookies and the hashed refresh token record.

## Chrome Extension
The `extension/` folder contains a Chrome toolbar companion that mirrors the vault workflow.

### Load & Configure
1. Run the Flask server (`python src/app.py`).
2. Open `chrome://extensions`, enable **Developer mode**, choose **Load unpacked…**, and select the `extension/` directory.
3. Pin **Secure Auth Vault** from the extensions menu for quick access.
4. In the popup, set your server URL (defaults to `http://127.0.0.1:5000`). The value is saved via `chrome.storage`, so you can target remote deployments as well.

### Use the Popup
- Register or log in directly from the extension—the backend exposes JSON endpoints (`/api/auth/register`, `/api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`) that return JWTs and hashed refresh tokens specifically for API clients. No prior browser session is required.
- First-time vault setup still re-verifies the login password (via `/api/verify-login`) before accepting a passphrase; all encryption remains client-side (PBKDF2 → AES-GCM) inside the popup.
- Unlocks last five minutes, with a visible countdown; afterwards the extension wipes the key and re-locks automatically.
- Adding credentials reuses the zero-knowledge workflow: entries encrypt client-side, and the extension POSTs only ciphertext/nonce to `/api/vault`.
- Update `extension/manifest.json` if you want to restrict `host_permissions` to your production domain instead of using `<all_urls>`.

## Data Storage
- `src/app.db` (SQLite) holds:
  - `users`: username, Argon2 hash, per-user random vault salt.
  - `vault_items`: single row per user with ciphertext + nonce blobs and timestamps.
  - `refresh_tokens`: hashed refresh tokens with expirations for revocation.
- Delete `src/app.db` to reset the environment (useful for local testing after schema changes).

## Security Considerations & Learnings
- **Zero-knowledge architecture**: all vault encryption happens in the browser; the server lacks the key to decrypt user data, even with database access.
- **Argon2 everywhere it matters**: user passwords are hashed server-side; vault passphrases derive encryption keys via PBKDF2 in the client, and per-user salts harden against precomputation attacks.
- **CSRF defenses**: both HTML forms and JSON APIs enforce double-submit tokens to mitigate cross-site request forgery.
- **Credential verification at critical steps**: initial vault setup re-checks the login password server-side to prevent unauthorized passphrase creation if someone gains access to an unlocked device.
- **Session hardening**: access tokens live in short-lived JWTs, refresh tokens are hashed/restored server-side (no raw tokens in the DB), and cookies are `HttpOnly` + optionally `Secure`.
- **Rate limiting & lockouts**: mitigate brute-force attempts by tracking failures per username/IP combination and temporarily blocking offenders.
- **Auto-locking vault**: client clears derived keys and ciphertext after five minutes of inactivity to reduce exposure on shared machines.

## Next Steps / Ideas
- Integrate WebAuthn or hardware-backed keys for login.
- Add per-entry sharing with client-side re-encryption.
- Replace PBKDF2 with Argon2id in the browser once Web Crypto support matures or via WASM.
- Package the front-end as a PWA for offline-ready vault access.

## License
This project is for educational purposes; no explicit license is provided. Adjust to your needs before deploying to production.
