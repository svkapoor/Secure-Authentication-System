# Secure Authentication System

This project intentionally starts with an insecure baseline so you can observe weaknesses before hardening.

## Phase 1: Baseline (hashing + JWT)
- Argon2id password hashing.
- JWT stored in an HttpOnly cookie for authentication.
- Simple register/login/logout flow.

## Run
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python src\app.py
```
