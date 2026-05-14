#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
EXTRA_OPTS="--enable-Werror"
JOBS=${JOBS:-"-j4"}

DOCA_LINK="${DOCA_LINK:-static}"

# DOCA .pc directory.
DOCA_PKGCONFIG=$(find /opt/mellanox/doca -name pkgconfig -type d 2>/dev/null \
                 | head -1)

DPDK_INSTALL_DIR="${DPDK_INSTALL_DIR:-$(pwd)/dpdk-dir}"
DPDK_VERSION_FILE="${DPDK_INSTALL_DIR}/cached-version"
if [ -f "${DPDK_VERSION_FILE}" ]; then
    DPDK_LIB=${DPDK_INSTALL_DIR}/lib/x86_64-linux-gnu
    export PKG_CONFIG_PATH="${DPDK_LIB}/pkgconfig:${DOCA_PKGCONFIG}${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
    export PATH="${DPDK_INSTALL_DIR}/bin:${PATH}"
    echo "Using cached DPDK $(cat "${DPDK_VERSION_FILE}") from ${DPDK_INSTALL_DIR}"
else
    export PKG_CONFIG_PATH="${DOCA_PKGCONFIG}${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
    DPDK_LIB=""
fi

if [ "$DOCA_LINK" = "shared" ]; then
    DOCA_LIB=${DOCA_PKGCONFIG%/pkgconfig}
    export LD_LIBRARY_PATH="${DPDK_LIB:+$DPDK_LIB:}${DOCA_LIB}:${LD_LIBRARY_PATH:-}"
fi
sudo ldconfig

EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=$DOCA_LINK --with-doca=$DOCA_LINK"

./boot.sh
./configure CFLAGS="${CFLAGS_FOR_OVS}" $EXTRA_OPTS
make $JOBS

if ! vswitchd/ovs-vswitchd -V 2>&1 | grep -q 'DOCA'; then
    echo "Expected 'DOCA' in ovs-vswitchd -V output for DOCA build." >&2
    vswitchd/ovs-vswitchd -V || true
    exit 1
fi

export DISTCHECK_CONFIGURE_FLAGS="$EXTRA_OPTS"
make distcheck ${JOBS} CFLAGS="${CFLAGS_FOR_OVS}" \
    TESTSUITEFLAGS="${JOBS} ${TEST_RANGE}" RECHECK=yes
