#!/bin/bash
#
# Diagnose fsync behaviour in the CI environment.
#
# Usage:
#   ./.ci/check-fsync.sh pre
#   ./.ci/check-fsync.sh post [PATH-TO-test-ovsdb]
#
# "pre" runs raw fsync/fdatasync tests and needs only a C compiler.
# "post" additionally exercises ovsdb log commit paths via test-ovsdb.

set -u

phase="${1:-pre}"
test_ovsdb="${2:-tests/test-ovsdb}"
cc="${CC:-cc}"

failures=0
passes=0

pass() {
    echo "PASS: $*"
    passes=$((passes + 1))
}

fail() {
    echo "FAIL: $*"
    failures=$((failures + 1))
}

setup_runtime_library_path() {
    local paths=""

    if [ -d "$(pwd)/dpdk-dir/lib/x86_64-linux-gnu" ]; then
        paths="$(pwd)/dpdk-dir/lib/x86_64-linux-gnu"
    fi

    local doca_pkgconfig
    doca_pkgconfig=$(find /opt/mellanox/doca -name pkgconfig -type d \
                     2>/dev/null | head -1)
    if [ -n "${doca_pkgconfig}" ]; then
        local doca_lib="${doca_pkgconfig%/pkgconfig}"
        if [ -d "${doca_lib}" ]; then
            paths="${paths}${paths:+:}${doca_lib}"
        fi
    fi

    if [ -n "${paths}" ]; then
        LD_LIBRARY_PATH="${paths}${LD_LIBRARY_PATH:+:${LD_LIBRARY_PATH}}"
        export LD_LIBRARY_PATH
    fi
}

resolve_test_ovsdb_binary() {
    local candidate

    for candidate in tests/.libs/test-ovsdb "${test_ovsdb}"; do
        if [ -x "${candidate}" ]; then
            echo "${candidate}"
            return 0
        fi
    done
    return 1
}

print_env() {
    echo "=== fsync check environment ==="
    echo "phase: ${phase}"
    echo "pwd: $(pwd)"
    echo "compiler: ${cc}"
    uname -a
    df -T . 2>/dev/null || df .
    if command -v findmnt >/dev/null 2>&1; then
        findmnt -T . -o TARGET,FSTYPE,OPTIONS 2>/dev/null || true
    fi
    if command -v stat >/dev/null 2>&1; then
        stat -f . 2>/dev/null || stat -c 'fs type: %s' -f . 2>/dev/null || true
    fi
    echo
}

run_raw_fsync_checks() {
    local workdir

    workdir=$(mktemp -d)
    trap 'rm -rf "$workdir"' RETURN

    cat > "${workdir}/fsync-check.c" <<'EOF'
#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int
report_fsync(const char *label, int fd)
{
    if (fsync(fd) == 0) {
        printf("OK %s\n", label);
        return 0;
    }

    printf("FAIL %s fsync errno=%d (%s)\n",
           label, errno, strerror(errno));
    return 1;
}

static int
report_fdatasync(const char *label, int fd)
{
#ifdef _POSIX_SYNCHRONIZED_IO
    if (fdatasync(fd) == 0) {
        printf("OK %s\n", label);
        return 0;
    }

    printf("FAIL %s fdatasync errno=%d (%s)\n",
           label, errno, strerror(errno));
    return 1;
#else
    printf("SKIP %s fdatasync (not supported)\n", label);
    return 0;
#endif
}

static int
report_dir_fsync(const char *label, const char *path)
{
    int fd = open(path, O_RDONLY | O_DIRECTORY);
    int rc = 0;

    if (fd < 0) {
        printf("FAIL %s open errno=%d (%s)\n",
               label, errno, strerror(errno));
        return 1;
    }

    if (fsync(fd) != 0) {
        printf("FAIL %s fsync errno=%d (%s)\n",
               label, errno, strerror(errno));
        rc = 1;
    } else {
        printf("OK %s\n", label);
    }

    close(fd);
    return rc;
}

int
main(void)
{
    int failures = 0;
    int fd;

    mkdir("dir", 0755);
    symlink("dir/db", "db");

    fd = open("plain", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, "x\n", 2) != 2) {
        printf("FAIL plain setup errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    failures += report_fsync("plain-file-fsync", fd);
    failures += report_fdatasync("plain-file-fdatasync", fd);
    close(fd);

    fd = open("dir/db", O_RDWR | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || write(fd, "x\n", 2) != 2) {
        printf("FAIL dir/db setup errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    failures += report_fsync("dir-db-fsync", fd);
    close(fd);

    fd = open("db", O_RDWR);
    if (fd < 0 || write(fd, "y\n", 2) != 2) {
        printf("FAIL symlink-db setup errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    failures += report_fsync("symlink-db-fsync", fd);
    close(fd);

    failures += report_dir_fsync("dir-fsync", "dir");
    failures += report_dir_fsync("parent-dir-fsync", ".");

    return failures ? 1 : 0;
}
EOF

    echo "=== raw fsync checks ==="
    pushd "${workdir}" >/dev/null
    if ! "${cc}" -std=c11 -Wall -Wextra -o fsync-check fsync-check.c; then
        fail "could not compile raw fsync checker with ${cc}"
        popd >/dev/null
        return
    fi

    if ./fsync-check; then
        pass "raw fsync/fdatasync checks"
    else
        fail "raw fsync/fdatasync checks"
    fi
    popd >/dev/null
    echo
}

run_ovsdb_fsync_check() {
    local stderr_file
    local binary
    local rc

    setup_runtime_library_path
    if ! binary=$(resolve_test_ovsdb_binary); then
        echo "SKIP: test-ovsdb not built yet"
        echo
        return
    fi

    echo "=== ovsdb log fsync checks (${binary}) ==="
    echo "LD_LIBRARY_PATH: ${LD_LIBRARY_PATH:-<unset>}"
    stderr_file=$(mktemp)
    trap 'rm -f "$stderr_file"' RETURN

    if "${binary}" -vconsole:warn log-fsync-check 2>"${stderr_file}"; then
        pass "test-ovsdb log-fsync-check"
    else
        rc=$?
        fail "test-ovsdb log-fsync-check exited with status ${rc}"
        if [ -s "${stderr_file}" ]; then
            echo "--- test-ovsdb stderr ---"
            cat "${stderr_file}"
        else
            echo "--- test-ovsdb produced no stderr output ---"
        fi
    fi

    if grep -q 'fsync failed' "${stderr_file}"; then
        fail "test-ovsdb logged fsync warnings"
        echo "--- test-ovsdb stderr ---"
        cat "${stderr_file}"
    else
        pass "test-ovsdb produced no fsync warnings"
    fi
    echo
}

print_env
run_raw_fsync_checks

if [ "${phase}" = post ]; then
    run_ovsdb_fsync_check
fi

echo "=== fsync check summary ==="
echo "passes: ${passes}"
echo "failures: ${failures}"

if [ "${failures}" -ne 0 ]; then
    exit 1
fi

exit 0
