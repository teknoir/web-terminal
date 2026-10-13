# wg-connect: the ProxyCommand used by SSH_PROXY_MODE=wireguard.
# NOTE: cmd/wg-connect lands in github.com/teknoir/wg-tunnel with work package A3;
# until then this stage (and so the image build) fails. Pin WG_TUNNEL_REF to a tag or sha for releases.
FROM golang:1.25-alpine AS wg
ARG WG_TUNNEL_REF=main
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