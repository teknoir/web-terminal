FROM python:3.11-alpine

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TERM=xterm-256color

WORKDIR /app

# Install system dependencies
RUN apk add --no-cache \
    bash \
    tini \
    openssh-client \
    libwebsockets

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