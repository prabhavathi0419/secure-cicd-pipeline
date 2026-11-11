# ---------- Stage 1: build (pip/caches stay here, NOT in the final image) ----------
FROM python:3.12-slim-trixie AS builder
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
# Copy only the dependency list first: this layer is cached until requirements change.
COPY requirements.txt .
# Install into an isolated prefix so the runtime stage can copy just the packages.
RUN pip install --prefix=/install -r requirements.txt

# ---------- Stage 2: runtime (small, non-root) ----------
FROM python:3.12-slim-trixie AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    APP_ENV=production APP_DB_PATH=/data/app.db
# Pick up security patches published after the base image was built, then clean apt caches
# (the cache would otherwise stay in the layer and bloat the image).
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*
# Non-root user with a fixed high UID; no login shell, no home directory.
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data && chown app:app /data \
 # The runtime never installs packages: remove the installer (smaller attack surface).
 && python -m pip uninstall -y pip wheel
COPY --from=builder /install /usr/local
WORKDIR /srv
COPY --chown=root:root app ./app
USER 10001:10001
EXPOSE 8000
# NOTE: no secrets here. APP_SECRET_KEY is injected at run time (compose / orchestrator).
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status==200 else 1)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header"]
