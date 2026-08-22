FROM python:3.11-slim-bookworm

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    RATHOLE_ENABLE_SERVER=1 \
    RATHOLE_BIN=/usr/local/bin/rathole

# System packages only for extraction + HTTPS downloads.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

# Dependencies are isolated in their own layer so application edits
# do not invalidate the pip install cache.
COPY requirements.txt .
RUN pip install --no-cache-dir --prefer-binary -r requirements.txt

# Pin Rathole to a released binary instead of querying the GitHub API.
# Railway builds for amd64 in the normal deployment path.
ARG RATHOLE_VERSION=v0.5.0
ARG RATHOLE_ASSET=rathole-x86_64-unknown-linux-gnu.zip
RUN curl -fsSL --retry 4 --retry-delay 2 \
      "https://github.com/rathole-org/rathole/releases/download/${RATHOLE_VERSION}/${RATHOLE_ASSET}" \
      -o /tmp/rathole.zip \
    && unzip -q /tmp/rathole.zip -d /tmp/rathole \
    && install -m 0755 /tmp/rathole/rathole /usr/local/bin/rathole \
    && rm -rf /tmp/rathole /tmp/rathole.zip

# The Railway HTTP domain targets this container port when PORT is not injected.
EXPOSE 8080

# Keep the final layer focused on runtime files.
COPY . .

RUN chmod +x install-rathole-agent.sh rathole_agent.py \
    && find . -type d -name '__pycache__' -prune -exec rm -rf {} + \
    && find . -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete

CMD ["python", "main.py"]
