# StackSift web — portable image (escape hatch).
# Build context: this directory (src/web). The app is self-contained:
# the diagnostic library is vendored under app/vendor/, and Alembic
# migrations run automatically at app startup (app/main.py run_migrations).
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

RUN useradd --create-home appuser && chown -R appuser:appuser /app
USER appuser

# Required env at runtime (set by the platform, never baked in):
#   DATABASE_URL            e.g. postgresql://user:pass@host:5432/db
#   STACKSIFT_PROXY_MODE    per-platform value (see escape-hatch runbook)
#   RESEND_API_KEY, FROM_EMAIL, APP_URL, OAuth client id/secret pairs
# $PORT is provided by the platform (defaults to 8000 locally).
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000} --no-proxy-headers"]
