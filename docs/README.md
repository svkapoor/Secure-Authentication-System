# Secure Authentication System

This project intentionally starts with an insecure baseline so you can observe weaknesses before hardening.

## Phase 1: Baseline (insecure)
- Plaintext password storage (do not use in production).
- Simple register/login/logout flow.

## Run
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python src\app.py
```
