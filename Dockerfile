FROM python:3.10.14-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PORT=5000 \
    SOLC_VERSION=0.8.25

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.lock .
RUN python -m pip install --no-cache-dir --require-hashes -r requirements.lock

COPY . .

RUN python -c "import solcx; solcx.install_solc('0.8.25')" && \
    mkdir -p /data && \
    useradd --create-home --uid 1000 auditoruser && \
    chown -R auditoruser:auditoruser /app /data && \
    chmod +x start.sh

USER auditoruser

EXPOSE 5000
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:' + __import__('os').environ.get('PORT', '5000') + '/health', timeout=3)"

CMD ["./start.sh"]
