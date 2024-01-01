#!/bin/bash

# Build images for ARM64 and AMD64
docker build -t ibehren1/vyos-fw-gui:arm64 .
docker build --platform=linux/amd64 -t ibehren1/vyos-fw-gui:amd64 .

# Push images to Docker Hub
docker push ibehren1/vyos-fw-gui:arm64
docker push ibehren1/vyos-fw-gui:amd64