# Multi-stage build keeps the runtime image free of build-only tooling
# (gcc, headers needed to compile numpy/scikit-learn/pyod wheels on some
# platforms). NOTE: this Dockerfile's syntax was validated (docker build
# parses it, resolves stages, correctly fails only at the external
# registry pull) but the actual image build could not be completed in the
# sandbox this was built in -- that sandbox's network policy blocks
# Docker Hub. DEPLOY.md says this explicitly rather than claiming a build
# verification that didn't happen; test the actual build in an
# environment with normal registry access before relying on it.
FROM python:3.11-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --default-timeout=120 --retries=10 --prefix=/install -r requirements.txt

FROM python:3.11-slim

# Runs as a non-root user -- a container running as root is a real
# privilege-escalation surface if the app is ever compromised, not just a
# compliance checkbox.
RUN groupadd -r app && useradd -r -g app app

WORKDIR /app
COPY --from=builder /install /usr/local
COPY app ./app
COPY scripts ./scripts

RUN chown -R app:app /app
USER app

ENV PYTHONUNBUFFERED=1 MPLCONFIGDIR=/tmp/mpl
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=3).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
