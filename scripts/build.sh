#!/bin/bash
# Script to run Docker build.

# Internal registry for publishing dev builds.
INTERNAL_REG="registry.internal.behrenshome.com"


#
# Set some colors.
CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'


#
# Determine which tag to apply to image.
if [ "${1}" == "Prod" ]; then
   BUILD_TYPE="Prod"
elif [ "${1}" == "PubDev" ]; then
   BUILD_TYPE="PubDev"
elif [ "${1}" == "Dev" ]; then
   BUILD_TYPE="Dev"
else
   BUILD_TYPE="Local"
fi

# Read the version number.
VERSION=`python3 -c 'import toml; c = toml.load("pyproject.toml"); print((c["project"]["version"]))'`
echo -e "\n${CYAN}Building version: ${VERSION}:${BUILD_TYPE}${NC}\n"
echo -e "v${VERSION}" > .version


#
# Run the bandit security scan on the codebase.
echo -e "\n${CYAN}#\n# Running Bandit security scan on codebase.${NC}\n"
bandit -c pyproject.toml -r .
if [ $? -ne 0 ]; then
    echo -e "{${RED}\n***\n*\n*   Error - Bandit security scan failed. Exiting.\n*\n***${NC}"
    exit 1
fi
echo -e "\n${GREEN}Bandit security scan completed.${NC}\n"


#
# Run pytest to validate the codebase.
echo -e "\n${CYAN}#\n# Running Pytest on codebase.${NC}\n"
pytest


#
# Run Docker Build and Publish
echo -e "\n${CYAN}#\n# Running Dockerbuild.${NC}\n"

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
    docker buildx build -f docker/Dockerfile \
        --platform=linux/arm64,linux/amd64 \
        --no-cache \
        --push \
        --tag ${DOCKER_USER}/fw-gui:${VERSION} \
        --tag ${DOCKER_USER}/fw-gui:latest .
fi

if [ "${BUILD_TYPE}" == "PubDev" ]; then
    docker buildx build -f docker/Dockerfile \
        --platform=linux/arm64,linux/amd64 \
        --no-cache \
        --push \
        --tag ${DOCKER_USER}/fw-gui:dev-${VERSION} \
        --tag ${INTERNAL_REG}/fw-gui:dev-${VERSION} \
        --tag ${INTERNAL_REG}/fw-gui:dev-latest .
fi

if [ "${BUILD_TYPE}" == "Dev" ]; then
    docker buildx build -f docker/Dockerfile \
        --platform=linux/arm64,linux/amd64 \
        --no-cache \
        --push \
        --tag ${INTERNAL_REG}/fw-gui:dev-${VERSION} \
        --tag ${INTERNAL_REG}/fw-gui:dev-latest .
fi

if [ "${BUILD_TYPE}" == "Local" ]; then
    docker buildx build -f docker/Dockerfile \
        --no-cache \
        --output type=docker \
        --tag fw-gui:${VERSION} .
fi

echo -e "\n${GREEN}${BUILD_TYPE} Build of ${VERSION} completed.${NC}"

exit 0
