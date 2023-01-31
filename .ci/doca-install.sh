#!/bin/bash

set -ev

# Install DOCA SDK packages.
#
# Download the DOCA host repo package from:
#   https://developer.nvidia.com/doca-downloads
#     deployment_platform=Host-Server, deployment_package=DOCA-Host,
#     target_os=Linux, Architecture=x86_64, Profile=doca-all
#
# DOCA installation also provides DPDK.

if [ -f /etc/os-release ]; then
    . /etc/os-release
fi

case "$ID" in
    ubuntu|debian)
        DOCA_REPO_PKG_URL="${DOCA_REPO_PKG_URL:?Set DOCA_REPO_PKG_URL to the .deb repo package URL}"

        wget -q "$DOCA_REPO_PKG_URL" -O /tmp/doca-repo.deb
        sudo dpkg -i /tmp/doca-repo.deb
        sudo apt-get update
        sudo apt-get install -y doca-networking-userspace
        ;;
    fedora|rhel|centos|rocky|almalinux)
        DOCA_REPO_PKG_URL="${DOCA_REPO_PKG_URL:?Set DOCA_REPO_PKG_URL to the .rpm repo package URL}"

        wget -q "$DOCA_REPO_PKG_URL" -O /tmp/doca-repo.rpm
        rpm -i /tmp/doca-repo.rpm
        dnf clean all
        dnf install -y doca-networking-userspace
        ;;
    *)
        echo "ERROR: Unsupported distribution: $ID" >&2
        exit 1
        ;;
esac
