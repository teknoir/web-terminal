#!/bin/bash
set -euo pipefail

# Default values
TAG=${TAG:-$(date +%Y%m%d-%H%M%S)}
IMAGE_NAME="docker.io/tekn0ir/web-terminal:${TAG}"

echo "Building Docker image: ${IMAGE_NAME}..."

# Build the docker image
docker buildx build \
  --platform=linux/amd64 \
  --push \
  --tag "${IMAGE_NAME}" \
  .

echo "Build finished successfully."
echo "Image: ${IMAGE_NAME}"

IMAGE_NAME="docker.io/tekn0ir/web-terminal:latest"

echo "Building Docker image: ${IMAGE_NAME}..."

# Build the docker image
docker buildx build \
  --platform=linux/amd64 \
  --push \
  --tag "${IMAGE_NAME}" \
  .

echo "Build finished successfully."
echo "Image: ${IMAGE_NAME}"