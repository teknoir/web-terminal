# wg-connect: the ProxyCommand used by SSH_PROXY_MODE=wireguard.
# WG_TUNNEL_REF is pinned to a wg-tunnel main commit sha; bump it for releases.
FROM golang:1.26-alpine AS wg
ARG WG_TUNNEL_REF=b1b2d6f5dafc2ba003dbff698944c740d02c2a45
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath github.com/teknoir/wg-tunnel/cmd/wg-connect@${WG_TUNNEL_REF}

FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    bash \
    zsh \
    git \
    tini \
    openssh-client \
    libwebsockets

COPY --from=wg /out/wg-connect /usr/local/bin/wg-connect

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application source
COPY app/ app/
COPY docker-entrypoint.sh .

# Prepare entrypoint script
RUN chmod +x docker-entrypoint.sh && \
    cp docker-entrypoint.sh /usr/bin/docker-entrypoint.sh

ENTRYPOINT ["/sbin/tini", "--", "docker-entrypoint.sh"]