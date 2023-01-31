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
    dpdk_pc="${DPDK_LIB}/pkgconfig:${DOCA_PKGCONFIG}"
    cfg_tail="${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
    export PKG_CONFIG_PATH="${dpdk_pc}${cfg_tail}"
    export PATH="${DPDK_INSTALL_DIR}/bin:${PATH}"
    dv=$(cat "${DPDK_VERSION_FILE}")
    echo "Using cached DPDK ${dv} from ${DPDK_INSTALL_DIR}"
else
    cfg_tail="${PKG_CONFIG_PATH:+:${PKG_CONFIG_PATH}}"
    export PKG_CONFIG_PATH="${DOCA_PKGCONFIG}${cfg_tail}"
    DPDK_LIB=""
fi

if [ "$DOCA_LINK" = "shared" ]; then
    DOCA_LIB=${DOCA_PKGCONFIG%/pkgconfig}
    prefix="${DPDK_LIB:+$DPDK_LIB:}${DOCA_LIB}"
    export LD_LIBRARY_PATH="${prefix}:${LD_LIBRARY_PATH:-}"
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
