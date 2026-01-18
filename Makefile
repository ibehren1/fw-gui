# Copyright © 2023-2026 Isaac Behrens. All rights reserved.

SHELL := /usr/bin/env bash -euo pipefail -c

# If you want to push to Docker Hub fill in the following values or have them
# 	set externally as environment variables.
# DOCKER_USER  = "<Docker Hub Username>"
# DOCKER_PAT   = "<Docker Hub Personal Access Token>"


######## Local Build (default) ########

# Build a container image and keep on local machine with the following tags:
#	fw-gui:${VERSION} tag.
local:
	./scripts/build.sh


######## Local Dev Build ########

# Build a container image and push to Developer's local registry with the
# following tags:
#	${INTERNAL_REG}/fw-gui:dev-latest
# 	${INTERNAL_REG}/fw-gui:dev-${VERSION}
dev:
	./scripts/build.sh Dev


######## Public Dev Build ########

# Build a container image and push to Docker Hub with the following tags:
#	${DOCKER_USER}/fw-gui:dev-latest
#	${DOCKER_USER}/fw-gui:dev-${VERSION}
pubdev:
	./scripts/build.sh PubDev


######## PROD BUILD ########

# Build a container image and push to Docker Hub with the following tags:
#	${DOCKER_USER}/fw-gui:latest
#	${DOCKER_USER}/fw-gui:${VERSION}
prod:
	./scripts/build.sh Prod
