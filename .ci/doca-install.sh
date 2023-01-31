#!/bin/bash

set -ev

# Install DOCA SDK packages.
#
# Download the DOCA host repo package from:
#   https://developer.nvidia.com/doca-downloads
#     deployment_platform=Host-Server, deployment_package=DOCA-Host,
#     target_os=Linux, Architecture=x86_64, Profile=doca-all
#

DOCA_REPO_PKG_URL="${DOCA_REPO_PKG_URL:?Set to .deb repo package URL}"

wget -q "$DOCA_REPO_PKG_URL" -O /tmp/doca-repo.deb
sudo dpkg -i /tmp/doca-repo.deb
sudo apt-get update
sudo apt-get install -y dpdk-community-dev \
    libdoca-sdk-flow-dev libdoca-sdk-dpdk-bridge-dev

