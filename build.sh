#!/bin/bash
# Script to run Docker build.

# Determine which tag to apply to image.
if [ "${1}" == "Prod" ]; then
   BUILD_TYPE="Prod" 
else
   BUILD_TYPE="Dev" 
fi

# Read the version number.
VERSION=$(<.version)
echo -e "\nBuilding version: ${VERSION}:${BUILD_TYPE}\n"

# Run the bandit security scan on the codebase.
echo -e "\nRunning Bandit security scan on codebase.\n"
bandit -r .
if [ $? -ne 0 ]; then
    echo -e "\n***\n*\n*   Error - Bandit security scan failed. Exiting.\n*\n***"
    exit 1
fi
echo -e "\nBandit security scan completed.\n"

# Set the Docker Hub username and password
docker login -u ${DOCKER_USER} -p ${DOCKER_PAT}

# Build images for ARM64 and AMD64.
docker buildx create \
    --use \
    --platform=linux/arm64,linux/amd64 \
    --name multi-platform-builder

docker buildx inspect \
    --bootstrap

if [ "${BUILD_TYPE}" == "Prod" ]; then
    docker buildx build \
        --platform=linux/arm64,linux/amd64 \
        --no-cache \
        --push \
        --tag ${DOCKER_USER}/fw-gui:${VERSION} \
        --tag ${DOCKER_USER}/fw-gui:latest .
else
    docker buildx build \
        --platform=linux/arm64,linux/amd64 \
        --no-cache \
        --push \
        --tag registry.internal.behrenshome.com/fw-gui:dev-${VERSION} \
        --tag registry.internal.behrenshome.com/fw-gui:dev-latest .
fi

echo -e "\n${BUILD_TYPE} Build of ${VERSION} completed."