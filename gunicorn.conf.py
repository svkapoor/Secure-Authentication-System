import multiprocessing
import os

# Cloud Run provides PORT; default for local dev.
bind = f"0.0.0.0:{os.environ.get('PORT', '8080')}"

# Use a sensible default based on CPU count.
workers = int(os.environ.get("WEB_CONCURRENCY", multiprocessing.cpu_count() * 2 + 1))

threads = int(os.environ.get("GUNICORN_THREADS", "1"))
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))

accesslog = "-"
errorlog = "-"
