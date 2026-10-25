FROM --platform=linux/amd64 python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update \
    && apt-get install --no-install-recommends -y ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN set -eu; \
    curl -fsSL \
      "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz" \
      -o /tmp/gitleaks.tar.gz; \
    echo "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb  /tmp/gitleaks.tar.gz" \
      | sha256sum -c -; \
    tar -xzf /tmp/gitleaks.tar.gz -C /usr/local/bin gitleaks; \
    chmod 0755 /usr/local/bin/gitleaks; \
    rm /tmp/gitleaks.tar.gz

RUN set -eu; \
    curl -fsSL \
      "https://github.com/google/osv-scanner/releases/download/v1.9.2/osv-scanner_linux_amd64" \
      -o /usr/local/bin/osv-scanner; \
    echo "d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b  /usr/local/bin/osv-scanner" \
      | sha256sum -c -; \
    chmod 0755 /usr/local/bin/osv-scanner

COPY backend/requirements.txt ./requirements.txt
RUN python -m pip install --no-cache-dir -r requirements.txt \
    && python -m venv /opt/semgrep \
    && /opt/semgrep/bin/python -m pip install --no-cache-dir semgrep==1.182.1

ENV PATH="/opt/semgrep/bin:${PATH}"

COPY backend/app ./app

RUN useradd --create-home --uid 10001 app \
    && chown -R app:app /app

USER app

EXPOSE 10000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-10000}"]
