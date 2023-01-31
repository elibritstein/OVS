#!/bin/bash

set -o errexit
set -x

CFLAGS_FOR_OVS="-g -O2"
EXTRA_OPTS="--enable-Werror"
JOBS=${JOBS:-"-j4"}

DOCA_LINK="${DOCA_LINK:-static}"

for pc_dir in $(find /opt/mellanox -name pkgconfig -type d 2>/dev/null); do
    PKG_CONFIG_PATH="${pc_dir}:${PKG_CONFIG_PATH}"
done
export PKG_CONFIG_PATH

if [ "$DOCA_LINK" = "shared" ]; then
    DOCA_LIB=$(find /opt/mellanox -name pkgconfig -type d 2>/dev/null \
               | head -1 | sed 's|/pkgconfig$||')
    export LD_LIBRARY_PATH="${DOCA_LIB}:${LD_LIBRARY_PATH}"
fi
sudo ldconfig

if [ "$CC" = "clang" ]; then
    CFLAGS_FOR_OVS="${CFLAGS_FOR_OVS} -Wno-error=unused-command-line-argument"
fi

EXTRA_OPTS="$EXTRA_OPTS --with-dpdk=$DOCA_LINK --with-doca=$DOCA_LINK"

if [ "$DOCA_LINK" = "shared" ]; then
    EXTRA_OPTS="$EXTRA_OPTS --enable-shared"
fi

./boot.sh
./configure CFLAGS="${CFLAGS_FOR_OVS}" $EXTRA_OPTS
make $JOBS
