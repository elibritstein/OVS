#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
EXTRA_OPTS="--enable-Werror"
JOBS=${JOBS:-"-j4"}

DOCA_LINK="${DOCA_LINK:-static}"

DPDK_INSTALL_DIR="$(pwd)/dpdk-dir"
DPDK_LIB="${DPDK_INSTALL_DIR}/lib/x86_64-linux-gnu"
DOCA_PKGCONFIG=$(find /opt/mellanox/doca -name pkgconfig -type d \
                 2>/dev/null | head -1)

if [ ! -f "${DPDK_INSTALL_DIR}/cached-version" ]; then
    echo "Could not find DPDK in ${DPDK_INSTALL_DIR}"
    exit 1
fi

echo "Found cached DPDK $(cat ${DPDK_INSTALL_DIR}/cached-version)" \
     "build in ${DPDK_INSTALL_DIR}"

PKG_CONFIG_PATH="${DPDK_LIB}/pkgconfig:${DOCA_PKGCONFIG}:${PKG_CONFIG_PATH}"
export PKG_CONFIG_PATH
export PATH="${DPDK_INSTALL_DIR}/bin:${PATH}"

if [ "$DOCA_LINK" = "shared" ]; then
    DOCA_LIB="${DOCA_PKGCONFIG%/pkgconfig}"
    export LD_LIBRARY_PATH="${DPDK_LIB}:${DOCA_LIB}:${LD_LIBRARY_PATH}"
fi

sudo ldconfig
EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=$DOCA_LINK --with-doca"

./boot.sh
./configure CFLAGS="${CFLAGS_FOR_OVS}" $EXTRA_OPTS
make ${JOBS} check TESTSUITEFLAGS="${JOBS} RECHECK=yes"

ovs_version=$(vswitchd/ovs-vswitchd -V 2>&1)
dpdk_version=$(pkg-config --modversion libdpdk)

if ! echo "$ovs_version" | grep -q 'DOCA'; then
    echo "Expected 'DOCA' in ovs-vswitchd -V output." >&2
    echo "$ovs_version"
    exit 1
fi

if ! echo "$ovs_version" | grep -q "DPDK ${dpdk_version}"; then
    echo "Expected 'DPDK ${dpdk_version}' in ovs-vswitchd -V output." >&2
    echo "Got: $ovs_version" >&2
    exit 1
fi
