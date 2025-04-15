# Copyright © 2023-2025 Isaac Behrens. All rights reserved.

SHELL := /usr/bin/env bash -euo pipefail -c


#
# Local Build (default)
#

# Build a container image and keep on local machine with the
#	fw-gui:${VERSION} tag.
local:
	./scripts/build.sh


#
# Local Dev Build
#

# Build a container image and push to Developer's local registry with the
# 	${INTERNAL_REG}/fw-gui:dev-${VERSION} and ${INTERNAL_REG}/fw-gui:dev-latest tags.
dev:
	./scripts/build.sh Dev


#
# Public Dev Build
#

# Build a container image and push to Docker Hub with the 
#	${DOCKER_USER}/fw-gui:dev-${VERSION} and ${DOCKER_USER}/fw-gui:dev-latest tags.
pubdev:
	./scripts/build.sh PubDev


#
# PROD BUILD
#

# Build a container image and push to Docker Hub with the
#	${DOCKER_USER}/fw-gui:${VERSION} and ${DOCKER_USER}/fw-gui:latest tags.
prod:
	./scripts/build.sh Prod