#!/bin/bash
set -euo pipefail

# Default values
PROJECT_ID=${PROJECT_ID:-"teknoir"}
TAG=${TAG:-$(date +%Y%m%d-%H%M%S)}
IMAGE_NAME="us-central1-docker.pkg.dev/${PROJECT_ID}/web-terminal:${TAG}"

echo "Building Docker image: ${IMAGE_NAME}..."

# Build the docker image
docker buildx build \
  --platform=linux/amd64 \
  --push \
  --tag "${IMAGE_NAME}" \
  .

echo "Build finished successfully."
echo "Image: ${IMAGE_NAME}"
