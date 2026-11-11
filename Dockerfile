# syntax=docker/dockerfile:1
# ---------- Stage 1: build (compilers/caches stay here, NOT in the final image) ----------
FROM python:3.12-slim-trixie AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# Copy only the dependency list first: this layer is cached until requirements change.
COPY requirements.txt .
# pip is removed from the venv afterwards: the runtime image never needs a package installer.
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install -r requirements.txt \
 && /opt/venv/bin/pip uninstall -y pip

# ---------- Stage 2: runtime (small, non-root) ----------
FROM python:3.12-slim-trixie AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:$PATH" \
    APP_ENV=production APP_DB_PATH=/data/app.db
# Non-root user with a fixed high UID; no login shell, no home directory contents.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data && chown app:app /data
COPY --from=builder /opt/venv /opt/venv
# Remove the base image's pip too (smaller attack surface, fewer scanner findings).
RUN /usr/local/bin/python -m pip uninstall -y pip wheel 2>/dev/null || true
WORKDIR /srv
COPY --chown=root:root app ./app
USER 10001:10001
EXPOSE 8000
# NOTE: no secrets here. APP_SECRET_KEY is injected at run time (compose / orchestrator).
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
