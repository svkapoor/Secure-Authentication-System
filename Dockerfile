FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY src ./src
COPY gunicorn.conf.py ./

EXPOSE 8080

CMD ["gunicorn", "-c", "gunicorn.conf.py", "app:app"]
