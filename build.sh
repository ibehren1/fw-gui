#!/bin/bash

docker build -t ibehren1/vyos-fw-gui:arm64 .
docker build --platform=linux/amd64 -t ibehren1/vyos-fw-gui:amd64 .