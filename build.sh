#!/bin/bash

# Source the .env to set the version number
. .env

# Set the Docker Hub username and password
docker login -u ${DOCKER_USER} -p ${DOCKER_PAT}

# Build images for ARM64 and AMD64
docker buildx create \
    --use \
    --platform=linux/arm64,linux/amd64 \
    --name multi-platform-builder

docker buildx inspect \
    --bootstrap

docker buildx build \
    --platform=linux/arm64,linux/amd64 \
    --push \
    --no-cache \
    --tag ${DOCKER_USER}/fw-gui:latest \
    --tag ${DOCKER_USER}/fw-gui:${VERSION} .
