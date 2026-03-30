#!/usr/bin/env bash

# Each line describes an option
#
# Examples
#
# Short + long option without parameter
#     help|h # Print this help.
# Long only option without parameter
#     rebuild # Force rebuilding everything.
# Long option accepting any parameter
#     cc= # Compiler to use.
# Long option accepting only some parameters
#     buildtype=debug|release # Build type for everything
#
# Specification:
#
# <match[|match]> list of 1 or more acceptable match.
#                 Long matches (>1 char) are added as `--<match>`.
#                 Short matches (=1 char) are added as `-<match>`.
# =[pattern[|pattern]] if this option takes a parameter
#                      and if specified, which parameters.
# #<description>  The description to print for this option in the usage screen.
#
options_parser_OPTS='
help|h # Print this help.
verbose|v # More prints.
dry-run|n # Print commands without executing.
check-libs|c # Check library versions.
rebuild # Force rebuilding everything.
rebuild-doca # Force rebuilding DOCA.
rebuild-nvhws # Force rebuilding nv_hws.
rebuild-rdma-core # Force rebuilding rdma-core.
recompile # Force OVS reconfiguration.
asan # Build with address sanitizer. Also enables debug.
asan-dpdk # Build DPDK with address sanitizer. Also enables debug.
sparse # Build with sparse checker. Also enables debug.
print-deps|deps # Print dependencies needed for the build.
install-deps # Install dependencies needed for the build.
install-ovs # Install OVS. Executed with sudo, requires privileged user.
build-rpm # Build ovs rpm.
build-deb # Build ovs deb.
info # Build with CFLAGS="$INFO_CFLAGS". Does not change build type.
debug  # Build with CFLAGS="$DEBUG_CFLAGS". Does not change build type.
doca-mode=host|dpu # Build DOCA in host or DPU mode.
disable-doca-telemetry # Disable DOCA Telemetry support and ignore CollectX.
buildtype=debug|release # Build type for everything.
buildtype-doca=debug|release # Build type for DOCA.
buildtype-nvhws=debug|release # Build type for libnvhws.
buildtype-rdma-core=debug|release # Build type for rdma-core.
cc= # Compiler to use.
nproc= # Number of cores to use.
dpdk-src-dir= # Path to existing dpdk source tree.
dpdk-install-dir= # Destination for dpdk build.
doca-src-dir= # Path to existing doca source tree.
doca-install-dir= # Destination for doca build.
nvhws-src-dir= # Path to existing nv_hws source tree.
nvhws-install-dir= # Destination for nv_hws build.
rdma-core-src-dir= # Path to existing rdma-core source tree.
rdma-core-install-dir= # Destination for rdma-core build.
'

# Invoke this script as:
#
#     options_parser_DEBUG=true ./build.sh
#
# To debug the options.
: ${options_parser_DEBUG:-false}

[ -f /etc/os-release ] && . /etc/os-release

OVS_SRC_DIR="$(readlink -f $(dirname "$0"))"
DPDK_SRC_DIR=""
DOCA_SRC_DIR=""
NVHWS_SRC_DIR=""
RDMA_CORE_SRC_DIR=""
LOGFILE="$OVS_SRC_DIR/build.log"
ASAN=
ASAN_DPDK=
SPARSE=
DRY_RUN=
VERBOSE=
REBUILD=
RECOMPILE=
REBUILD_DOCA=
REBUILD_NVHWS=
REBUILD_RDMA_CORE=
COMMON_CFLAGS="-g3 -fno-omit-frame-pointer"
INFO_CFLAGS="-O2 $COMMON_CFLAGS"
DEBUG_CFLAGS="-O0 $COMMON_CFLAGS"
CFLAGS=""
PKG_CONFIG_PATH=""
LD_LIBRARY_PATH=""
INSTALL_OVS=
NPROC=$(nproc)
BUILD_RPM=
BUILD_DEB=
ID=${ID:-"unknown"}
DISABLE_DOCA_TELEMETRY=
DOCA_MODE=

DPDK_PREFIX='$(readlink -f "${DPDK_SRC_DIR}/../dpdk-install")'
DOCA_PREFIX='$(readlink -f "${DOCA_SRC_DIR}/../doca-install")'
NVHWS_PREFIX='$(readlink -f "${NVHWS_SRC_DIR}/../nv_hws-install")'
RDMA_CORE_PREFIX='$(readlink -f "${RDMA_CORE_SRC_DIR}/../rdma-core-install")'

OS_DESC="${ID}${VERSION_ID}-$(uname -m)"
DPDK_DESC='$(describe_repository "${DPDK_SRC_DIR}")-${OS_DESC}'
DOCA_DESC='$(describe_repository "${DOCA_SRC_DIR}")-${OS_DESC}'
NVHWS_DESC='$(describe_repository "${NVHWS_SRC_DIR}")-${OS_DESC}'
RDMA_CORE_DESC='$(describe_repository "${RDMA_CORE_SRC_DIR}")-${OS_DESC}'

BUILDTYPE=release
BUILDTYPE_DPDK="$BUILDTYPE"
BUILDTYPE_NVHWS="$BUILDTYPE"
BUILDTYPE_RDMA_CORE="$BUILDTYPE"
BUILDTYPE_DOCA="$BUILDTYPE"

DPDK_INSTALL_DIR='${DPDK_PREFIX}/${DPDK_DESC}-${BUILDTYPE_DPDK}'
DOCA_INSTALL_DIR='${DOCA_PREFIX}/${DOCA_DESC}-${BUILDTYPE_DOCA}'
NVHWS_INSTALL_DIR='${NVHWS_PREFIX}/${NVHWS_DESC}-${BUILDTYPE_NVHWS}'
RDMA_CORE_INSTALL_DIR='${RDMA_CORE_PREFIX}/${RDMA_CORE_DESC}-${BUILDTYPE_RDMA_CORE}'

# Host CPU from QEMU on Macos M1 will not expose correct CPU info.
# In this case, fallback on a generic platform description for DPDK.
DPDK_MESON_EXTRA=""
MIDR_EL1_PATH='/sys/devices/system/cpu/cpu0/regs/identification/midr_el1'
MIDR_EL1=$(cat $MIDR_EL1_PATH 2> /dev/null)

# Colors
YELLOW='\e[33m'
CYAN="\033[0;36m"
RED="\033[0;31m"
NC="\e[0m"

unset PAGER
unset LESS

function git_get_last_tag() {
    local dir=${1:-$PWD}
    git -C "$dir" describe --abbrev=0 --tags 2> /dev/null
}

function git_get_tag_content() {
    local dir="${1:-$PWD}"
    local tag="${2:-$(git_get_last_tag "$dir")}"
    [ "$tag" ] && git -C "$dir" tag -l --format='%(contents)' $tag
}

function get_doca_ref_from_last_ovs_build() {
    # In the following tagged tree:
    #
    #   abcdef fourth commit (HEAD -> <branch>)
    #   001abc third commit
    #   000def second commit (tag: foo, tag: bar)
    #   000abc initial commit
    #
    # We want to find within all tags on the second commit (foo and bar),
    # the one that was used to tag the last OVS build.

    local dir="${1:-$PWD}"
    local last_tagged_commit=$(git -C "$dir" rev-parse $(git_get_last_tag "$dir")^{commit})
    local ref

    [ "$last_tagged_commit" ] || return
    for tag in $(git -C "$dir" tag --points-at $last_tagged_commit); do
        ref=$(git_get_tag_content "$dir" "$tag" | grep 'refs/head' | cut -f1)
        if [ "$ref" ]; then
            printf "%s" "$ref"
            return
        fi
    done
}

# Print a short string uniquely identifying the state of
# the source repository provided in '$1'.
# $1: A directory, pointing to either a git repository
#     or an archive of one.
function describe_repository() {
    local dir="$(readlink -f $1)"
    local desc
    [ -d "$dir" ] || return
    if [ -d "$dir/.git" ]; then
        # If a git repository, description is in order of:
        #   1. tag
        #   2. branch
        #   3. sha1
        desc=$(git -C "$dir" describe --exact-match --tags 2> /dev/null)
        [ ! "$desc" ] && desc=$(git -C "$dir" rev-parse --abbrev-ref HEAD | grep -v HEAD)
        [ ! "$desc" ] && desc=$(git -C "$dir" rev-parse --short HEAD)
    else
        [ -f "$dir/VERSION" ] && desc=$(cat "$dir/VERSION")
    fi
    [ ! "$desc" ] && desc="unknown"
    printf "$desc"
}

# Match a pattern in a string.
# $1: Pattern to match.
# $2: Haystack to search.
# Example:
#   if fnmatch '-O*|*\ -O*' "$CFLAGS_AUTO $CFLAGS" ; then
fnmatch() { eval "case \"\$2\" in $1) return 0 ;; *) return 1 ;; esac" ; }

# Evaluate $1 and set itself to the result.
# e.g. 'FOO=/tmp; BAR='${FOO}/path';
# reflect BAR ==> BAR is set to '/tmp/path'
function reflect() { eval $1=$(eval echo \$$1); }

function quote() {
tr '\n' ' ' <<EOF | grep '^[-[:alnum:]_=,./:]* $' >/dev/null 2>&1 && { echo "$1" ; return 0; }
$1
EOF
    printf %s\\n "$1" |
        sed -e "s/'/'\\\\''/g" -e "1s/^/'/" \
            -e "\$s/\$/'/" \
            -e "s#^'\([-[:alnum:]_,./:]*\)=\(.*\)\$#\1='\2#"
}

printf "" > "$LOGFILE"
function logfile_append() {
    echo "$@" >> "$LOGFILE"
}

cmdline=$(quote "$0")
for i ; do cmdline="$cmdline $(quote "$i")" ; done
logfile_append "#!/usr/bin/env bash"
logfile_append
logfile_append "# This log was generated by:"
logfile_append "# $cmdline"
logfile_append

function elog() {
    logfile_append "# ERROR: $*"
    echo -e "${RED}ERROR: $*${NC}" >&2
}

function err() {
    elog "$*"
    exit 1
}

function warn () {
    logfile_append "# WARNING: $*"
    echo -e "# ${YELLOW}WARNING: $*${NC}"
}

function log() {
    logfile_append "# $*"
    echo -e "# ${CYAN}$*${NC}"
}

function vlog() {
    if [ "$VERBOSE" ]
    then log "$*"
    else logfile_append "# $*"
    fi
}

function execute() {
    local redirect
    case $1 in
    --into)
        if [ "$VERBOSE" ]
        then redirect="| tee -a $2"
        else redirect=">> $2"
        fi
        shift 2;;
    esac

    local line
    for i ; do line="$line$(quote "$i") " ; done
    logfile_append "$line"
    if [ "$DRY_RUN" ]; then
        echo "$line"
    else
        [ "$VERBOSE" ] && echo "$line"
        # Set pipefail for using tee but still catch error.
        set -o pipefail
        eval "$line $redirect" || err "Failed to execute: $line"
        set +o pipefail
    fi
}

function is_bluefield_system() {
    lspci -s 00:00.0 | grep -qi 'bluefield'
}
is_bluefield_system && DOCA_MODE=dpu || DOCA_MODE=host

function check_meson_if_rebuild_needed() {
    local src_dir=${1:?missing arg}
    local install_dir=${2:?missing arg}
    local opts="$src_dir/build/meson-info/intro-buildoptions.json"
    local rc=0
    if [ -f $opts ]; then
        grep -q "$install_dir" $opts && rc=1 && RECOMPILE=true
    fi
    return $rc
}

function check_meson_if_recompile_needed() {
    [ "$DRY_RUN" ] && return
    ninja -n -C build install | grep -q "\[0/1\] Installing files." || RECOMPILE=true
}

function rebuild_dpdk() {
    [ -z "$DPDK_SRC_DIR" ] && return
    local build
    execute pushd "$DPDK_SRC_DIR"
    if [ -e "$DPDK_SRC_DIR/build/build.ninja" ]; then
        if [ "$REBUILD" ] ||
           check_meson_if_rebuild_needed $DPDK_SRC_DIR $DPDK_INSTALL_DIR; then
            build=true
        fi
        check_meson_if_recompile_needed
        if [ "$build" ]; then
            log "Rebuilding DPDK"
            execute rm -fr "$DPDK_SRC_DIR/build"
        elif [ "$RECOMPILE" ]; then
            log "Recompiling DPDK"
        else
            log "DPDK is already configured"
            execute popd
            return
        fi
    else
        log "Building DPDK"
        build=true
    fi

    [ "$ASAN_DPDK" ] && DPDK_MESON_EXTRA+=" -Db_sanitize=address"

    if [ "$DOCA_MODE" = "dpu" ]; then
        DPDK_MESON_EXTRA+=" -Dplatform=bluefield"
    elif [ "$MIDR_EL1" = 0x00000000610f0000 ]; then
        DPDK_MESON_EXTRA+=" -Dplatform=generic"
    fi

    local DPDK_OUT=/tmp/dpdk_out
    log "Build output: $DPDK_OUT"
    local DPDK_HEAD="DPDK HEAD is: $(git -C "$DPDK_SRC_DIR" --no-pager log --oneline -1)"
    log "$DPDK_HEAD"
    printf "%s\n" "$DPDK_HEAD" > "$DPDK_OUT"
    if [ "$build" ]; then
        execute --into "$DPDK_OUT" \
                meson setup -Dc_args="$CFLAGS" --buildtype=$BUILDTYPE_DPDK $DPDK_MESON_EXTRA \
                      -Dtests=false -Denable_drivers=bus/auxiliary,*/mlx5,mempool/*,net/vhost \
                      -Dmachine=default -Dmax_ethports=1024 --prefix="$DPDK_INSTALL_DIR" \
                      build
    fi
    execute --into "$DPDK_OUT" ninja -j $NPROC -C build install
    execute popd
}

function rebuild_rdma_core() {
    local install_dir="$RDMA_CORE_INSTALL_DIR"
    local src_dir="$RDMA_CORE_SRC_DIR"
    local build_dir="$src_dir/build"
    local out_file=/tmp/rdma-core_out
    local need_setup

    [ "$src_dir" ] || return
    execute pushd "$src_dir"

    if [ -e "$src_dir/build/build.ninja" ]; then
        if [ "$REBUILD" ] || [ "$REBUILD_RDMA_CORE" ]; then
            need_setup=yes
        fi
        if [ "$need_setup" ]; then
            log "Rebuilding rdma-core"
            execute rm -fr "$src_dir/build"
        else
            log "rdma-core is already installed"
            execute popd
            return
        fi
    else
        log "Building rdma-core"
        need_setup=yes
    fi

    if [ "$need_setup" ]; then
         execute mkdir -p "$build_dir"
         execute pushd "$build_dir"
         execute --into "$out_file" cmake -GNinja \
                                          -DENABLE_STATIC=1 \
                                          -DNO_MAN_PAGES=1 \
                                          -DNO_PYVERBS=1 \
                                          -DCMAKE_INSTALL_PREFIX="$install_dir" \
                                          ..
         execute popd
    fi
    execute --into "$out_file" ninja -j $NPROC -C build install
    execute popd

    REBUILD_NVHWS=1
}

function rebuild_nv_hws() {
    [ -z "$NVHWS_SRC_DIR" ] && return
    local build
    execute pushd "$NVHWS_SRC_DIR"
    if [ -e "$NVHWS_SRC_DIR/build/build.ninja" ]; then
        if [ "$REBUILD" ] || [ "$REBUILD_NVHWS" ] ||
           check_meson_if_rebuild_needed $NVHWS_SRC_DIR $NVHWS_INSTALL_DIR; then
            build=true
        fi
        check_meson_if_recompile_needed
        if [ "$build" ]; then
            log "Rebuilding nv_hws"
            execute rm -fr "$NVHWS_SRC_DIR/build"
        elif [ "$RECOMPILE" ]; then
            log "Recompiling nv_hws"
        else
            log "nv_hws is already configured"
            execute popd
            return
        fi
    else
        log "Building nv_hws"
        build=true
    fi

    local NVHWS_OUT=/tmp/nv_hws_out
    log "Build output: $NVHWS_OUT"
    local NVHWS_HEAD="nv-hws HEAD is: $(git -C "$NVHWS_SRC_DIR" --no-pager log --oneline -1)"
    log "$NVHWS_HEAD"
    printf "%s\n" "$NVHWS_HEAD" > "$NVHWS_OUT"
    if [ "$build" ]; then
        execute --into "$NVHWS_OUT" \
                meson setup -Dc_args="$CFLAGS" \
                      --buildtype=$BUILDTYPE_NVHWS \
                      -Dpyhws=false -Dflexio=auto \
                      --prefix="$NVHWS_INSTALL_DIR" build
    fi
    execute --into "$NVHWS_OUT" ninja -j $NPROC -C build install
    execute popd
}

# $1: Commit ID
# $2: (optional) Git repository, default to $PWD
# Returns 'true' if the HEAD of the git repository contains
# the provided commit ID as an ancestor.
function git_commit_is_ancestor() {
    local sha=$1
    local dir=${2:-$PWD}

    if [ ! -e "$dir/.git" ] ||
       [ "$(git -C ${dir} rev-parse --is-shallow-repository)" = "true" ]; then
        return 0
    fi

    if git -C ${dir} merge-base --is-ancestor $sha HEAD 2> /dev/null; then
        return 0
    else
        return 1
    fi
}

# nv-hws version format: <major>.0<YY><MM><DD> where DD is not zero-padded.
# Zero-pad the day field so that numerical comparison works correctly.
function normalize_nv_hws_version() {
    local major="${1%%.*}"
    local rest="${1#*.}"
    if [ "${#rest}" -eq 6 ]; then
        rest="${rest:0:5}0${rest:5:1}"
    fi
    echo "${major}.${rest}"
}

function doca_minimal_nvhws_version() {
    [ -z "$DOCA_SRC_DIR" ] && return
    grep -B1 'nvhws_version.version_compare' "$DOCA_SRC_DIR/configs/meson.build" |
        grep 'minimal_version = ' | cut -d= -f2 | xargs
}

function rebuild_doca() {
    [ -z "$DOCA_SRC_DIR" ] && return
    local build
    execute pushd "$DOCA_SRC_DIR"
    if [ -e "$DOCA_SRC_DIR/build/build.ninja" ]; then
        if [ "$REBUILD" ] || [ "$REBUILD_DOCA" ] ||
           check_meson_if_rebuild_needed $DOCA_SRC_DIR $DOCA_INSTALL_DIR; then
            build=true
        fi
        check_meson_if_recompile_needed
        if [ "$build" ]; then
            log "Rebuilding DOCA"
            execute rm -fr "$DOCA_SRC_DIR/build"
        elif [ "$RECOMPILE" ]; then
            log "Recompiling DOCA"
        else
            log "DOCA is already configured"
            execute popd
            return
        fi
    else
        log "Building DOCA"
        build=true
    fi

    local DOCA_MESON_EXTRA
    [ "$ASAN" ] && DOCA_MESON_EXTRA="-Db_sanitize=address"
    local DOCA_ENABLED_LIBS="flow,common,dpdk_bridge"
    local DOCA_ENABLED_DRIVERS="dpdk,nvhws"
    local DOCA_CFLAGS="$CFLAGS"
    [ "$BUILDTYPE_DOCA" == "debug" ] && DOCA_CFLAGS+=" -DDOCA_DEBUG"

    local DOCA_OUT=/tmp/doca_out
    log "Build output: $DOCA_OUT"
    local DOCA_HEAD="DOCA HEAD is: $(git -C "$DOCA_SRC_DIR" --no-pager log --oneline -1)"
    log "$DOCA_HEAD"
    printf "%s\n" "$DOCA_HEAD" > "$DOCA_OUT"

    if [ -f "$OVS_SRC_DIR/doca-min-sha.txt" ]; then
        local doca_min_sha=$(cat "$OVS_SRC_DIR/doca-min-sha.txt")
        if ! git_commit_is_ancestor $doca_min_sha $DOCA_SRC_DIR; then
            err "DOCA API mismatch: the git head is not based on $doca_min_sha, which is required"
        fi
    fi

    local doca_ref=$(get_doca_ref_from_last_ovs_build "$OVS_SRC_DIR")
    if [ "$doca_ref" ]; then
        vlog "doca_ref: $doca_ref"
        if ! git_commit_is_ancestor $doca_ref "$DOCA_SRC_DIR"; then
            local message="The tagged DOCA ref $doca_ref is not in this DOCA tree"
            [ "$CHECK_LIBS" ] && err "$message" || warn "$message"
        fi
    else
        vlog "No DOCA reference found from OVS build tag"
    fi

    local nvhws_min_ver=$(doca_minimal_nvhws_version)
    if [ ! "$nvhws_min_ver" ]; then
        warn "Unable to find the minimal required NVHWS version from DOCA source."
        warn "The implementation might have changed? Check $DOCA_SRC_DIR/configs/meson.build"
    elif [ "$NVHWS_VERSION" ]; then
        local nv_hws_ver=$(normalize_nv_hws_version "$NVHWS_VERSION")
        local nv_hws_min=$(normalize_nv_hws_version "$nvhws_min_ver")
        local message="DOCA requires nv-hws $nvhws_min_ver, provided version is $NVHWS_VERSION"
        if [ "$(echo "$nv_hws_ver < $nv_hws_min" | bc -l)" -ne 0 ]; then
            [ "$CHECK_LIBS" ] && err "$message" || warn "$message"
        else
            vlog "$message"
        fi
    fi

    local nvhws_tag_path="/auto/sw/release/doca/dpdk/doca-ci-nvhws.txt"
    local nvhws_tag_req=$(test -f "$nvhws_tag_path" && cat "$nvhws_tag_path")
    local nvhws_tag=$(git_get_last_tag "$NVHWS_SRC_DIR")
    if [ ! "$NVHWS_SRC_DIR" ] ||
       [ ! "$nvhws_tag_req" ] ||
       [ ! "$nvhws_tag" ]; then
        vlog "Unable to check the exact nv-hws tag requirement for DOCA"
    else
        local message="DOCA requires nv-hws tag $nvhws_tag_req, current tag is $nvhws_tag"
        if [ "$nvhws_tag" != "$nvhws_tag_req" ]; then
            [ "$CHECK_LIBS" ] && err "$message" || warn "$message"
        else
            vlog "$message"
        fi
    fi

    if [ "$build" ]; then
        if [ "$(uname -m)" = "aarch64" ] && [ "$DOCA_MODE" = "host" ]; then
            DOCA_MESON_EXTRA+=" -Darm_host_support=true"
        fi
        execute --into "$DOCA_OUT" \
                meson setup -Dc_args="$DOCA_CFLAGS" \
                      -Dcpp_args="$DOCA_CFLAGS" \
                      --buildtype=$BUILDTYPE_DOCA \
                      -Denable_libs=$DOCA_ENABLED_LIBS \
                      -Denable_drivers=$DOCA_ENABLED_DRIVERS \
                      -Ddisable_all_tools=true \
                      -Ddisable_all_services=true \
                      -Ddisable_all_extensions=true \
                      -Ddisable_symbol_hiding=true \
                      -Ddisable_system_tests=true \
                      -Denable_grpc_support=false \
                      -Denable_gpu_support=false \
                      -Ddisable_tool_flow_tune=true \
                      -Dverification_disable_testsuit=true \
                      $DOCA_MESON_EXTRA --prefix="$DOCA_INSTALL_DIR" build
    fi
    execute --into "$DOCA_OUT" ninja -j $NPROC -C build install
    execute popd
}

function rebuild_openvswitch() {
    local OVS_CONFIGURE_EXTRA

    [ "$ASAN" ] && OVS_CONFIGURE_EXTRA+=" --with-sanitizer"
    [ "$SPARSE" ] && OVS_CONFIGURE_EXTRA+=" --enable-sparse"
    [ "$DISABLE_DOCA_TELEMETRY" ] && OVS_CONFIGURE_EXTRA+=" --disable-doca-telemetry"

    execute pushd "$OVS_SRC_DIR"

    if [ -f config.log ] && ! grep -q "$PKG_CONFIG_PATH" config.log ; then
        # Needs rebuild because the PKG_CONFIG_PATH is not the same.
        REBUILD=1
    elif [ -e configure ] && [ -e Makefile ] && [ -e config.h ]; then
        # If a library was detected to be recompiled it sets RECOMPILE=true.
        # If not then there is no reason to force recompile of ovs.
        # Let 'make' decide.
        :
    else
        REBUILD=1
    fi

    if [ "$REBUILD" ]; then
        log "Rebuild openvswitch"
        execute ./boot.sh
        execute ./configure --prefix=/usr --localstatedir=/var --sysconfdir=/etc \
                            --with-dpdk=static --with-doca=static --with-nvhws=static \
                            --enable-Werror \
                            $OVS_CONFIGURE_EXTRA \
                            ${CC:+"CC=$CC"} \
                            ${CFLAGS:+"CFLAGS=$CFLAGS"}
    elif [ "$RECOMPILE" ]; then
        # Force recompiling ovs in case dpdk or doca changed.
        log "Recompile openvswitch"
        touch lib/ovs-doca.c
    else
        log "Building openvswitch"
    fi

    if [ "$BUILD_RPM" ]; then
        RPMBUILD_OPT="--with static --with dpdk --with doca --with nvhws_static --without check"
        [ "$ASAN" ] && RPMBUILD_OPT+=" --with sanitizer"
        [ "$DISABLE_DOCA_TELEMETRY" ] && RPMBUILD_OPT+=" --without doca_telemetry"
        if [ -n "$CFLAGS" ];  then
            local optflags=$(rpm --eval "%optflags" | sed -e 's/-D_FORTIFY_SOURCE=2 -Wp,//')
            optflags+=" $CFLAGS"
            RPMBUILD_OPT+=" --define 'optflags $optflags'"
        fi
        execute make rpm-fedora RPMBUILD_OPT="$RPMBUILD_OPT"
    elif [ "$BUILD_DEB" ]; then
        DEB_BUILD_OPTIONS="with-dpdk with-doca static nocheck parallel=$NPROC"
        EXTRA_CONFIGURE_OPTS="--with-nvhws=static"
        [ "$ASAN" ] && EXTRA_CONFIGURE_OPTS+=" --with-sanitizer"
        [ -n "$CFLAGS" ] && export DEB_CFLAGS_APPEND="$CFLAGS"
        [ "$DISABLE_DOCA_TELEMETRY" ] && EXTRA_CONFIGURE_OPTS+=" --disable-doca-telemetry"
        execute make debian-deb DEB_BUILD_OPTIONS="$DEB_BUILD_OPTIONS" EXTRA_CONFIGURE_OPTS="$EXTRA_CONFIGURE_OPTS"
    else
        execute make -j$NPROC -s

        if [ "$INSTALL_OVS" ]; then
            log "Install openvswitch"
            execute sudo make install -j$NPROC -s
        fi
    fi

    execute popd
}

function print_deps() {
    local deps

    if [ "$ID" == "ubuntu" ] || [ "$ID" == "debian" ]; then
        deps="\
python3-pyelftools meson libjson-c-dev protobuf-compiler binutils-dev
librdmacm-dev libibverbs-dev autoconf automake libtool gcc bc lftp graphviz
libunbound-dev libunwind-dev libssl-dev libelf-dev libnvhws-dev
libnuma-dev libpcap-dev dh-exec python3-all-dev python3-sortedcontainers
build-essential devscripts fakeroot python3-netifaces libdbus-1-dev
python3-sphinx python3-prometheus-client python3-enchant
libcap-ng-dev libsystemd-dev dh-python sparse
collectx-clxapidev
libarchive-dev libfdt-dev libdoca-sdk-dpdk-bridge-dev
nettle-dev libacl1-dev libzstd-dev liblz4-dev libbz2-dev libxml2-dev"
        if [ "$ASAN" ]; then
            if [[ "$VERSION_ID" =~ "20" ]]; then
                deps+=" libasan5 libubsan1"
            elif [[ "$VERSION_ID" =~ "22" ]]; then
                deps+=" libasan6 libubsan1"
            elif [[ "$VERSION_ID" =~ "24" ]]; then
                deps+=" libasan8 libubsan1"
            fi
        fi
        [ "$NVHWS_SRC_DIR" ] && deps+=" dpacc"
    else
        deps="\
librdmacm rdma-core-devel meson json-c-devel protobuf-compiler binutils-devel
zlib-devel libcurl-devel autoconf automake openssl-devel libtool nvhws-devel
unbound-devel unbound libpcap-devel libbsd-devel elfutils-libelf-devel
libunwind-devel rpm-build numactl-devel libcap-ng-devel python3-enchant
python3-sphinx python3-prometheus_client sparse bc systemd-devel
collectx-clxapidev
doca-sdk-dpdk-bridge-devel"
        if [ "$ASAN" ]; then
            deps+=" libasan libubsan"
        fi
        [ "$NVHWS_SRC_DIR" ] && deps+=" dpacc"
    fi

    echo $deps
}

function install_deps() {
    local deps=`print_deps`

    if [ "$ID" == "ubuntu" ] || [ "$ID" == "debian" ]; then
        execute sudo apt-get install -y $deps
    else
        execute sudo dnf install -y --skip-broken $deps
    fi
}

function update_pkg_config_path() {
    local path="$(eval echo \$$1_INSTALL_DIR)"
    local name=$2
    local lib
    local pkg
    local pc

    local pc=$(find "$path" -iname "$name" 2>/dev/null)
    [ -z "$pc" ] && [ "$DRY_RUN" ] && log "Missing $name. skip because of dry-run." && return
    [ -z "$pc" ] && err "Cannot find $name in $path"
    pkg="$(realpath $(dirname "$pc"))"
    lib="$(realpath $(dirname "$pkg"))"
    log "$name pkgconfig: $pkg"
    log "$name lib: $pkg"
    local version=$(grep Version $pc | cut -d' ' -f2-)
    eval $1_VERSION=$version
    log "$1_VERSION=$(eval echo \$$1_VERSION)"
    PKG_CONFIG_PATH+=":$pkg"
    LD_LIBRARY_PATH+=":$lib"
    PKG_CONFIG_PATH=${PKG_CONFIG_PATH##:}
    LD_LIBRARY_PATH=${LD_LIBRARY_PATH##:}
    execute export PKG_CONFIG_PATH=${PKG_CONFIG_PATH##:}
    execute export LD_LIBRARY_PATH=${LD_LIBRARY_PATH##:}
    log "`env | grep PKG_CONFIG_PATH`"
    log "`env | grep LD_LIBRARY_PATH`"
}

function update_dpdk_pkgconfig() {
    update_pkg_config_path DPDK "libdpdk.pc"
}

function update_doca_pkgconfig() {
    update_pkg_config_path DOCA "doca-flow.pc"
}

function update_nv_hws_pkgconfig() {
    [ -z "$NVHWS_SRC_DIR" ] && return
    update_pkg_config_path NVHWS "libnvhws.pc"
}

function update_rdma_core_pkgconfig() {
    [ "$RDMA_CORE_SRC_DIR" ] || return
    for pc in libibverbs.pc libmlx5.pc librdmacm.pc; do
        update_pkg_config_path RDMA_CORE "$pc"
    done
}

function update_install_dirs() {
    # The user arguments supersedes all logic:
    # If some were provided, they take priority over
    # autodetection and default fallbacks.

    if [ ! "$DPDK_INSTALL_DIR_set" ]; then
        if [ ! "$DPDK_SRC_DIR" ] && [ -d "$OVS_SRC_DIR/../dpdk" ]; then
            DPDK_SRC_DIR="$(readlink -f $OVS_SRC_DIR/../dpdk)"
            vlog "Detected DPDK source: $DPDK_SRC_DIR"
        elif [ ! "$DPDK_SRC_DIR" ] && [ -d "$OVS_SRC_DIR/../dpdk.org" ]; then
            DPDK_SRC_DIR="$(readlink -f $OVS_SRC_DIR/../dpdk.org)"
            vlog "Detected DPDK source: $DPDK_SRC_DIR"
        fi
        if [ -d "$DPDK_SRC_DIR" ]; then
            reflect DPDK_PREFIX
            reflect DPDK_DESC
            reflect DPDK_INSTALL_DIR
            log "DPDK source: $DPDK_SRC_DIR"
        else
            DPDK_INSTALL_DIR="/opt/mellanox/dpdk"
        fi
    fi
    log "DPDK installation: $DPDK_INSTALL_DIR"

    if [ ! "$DOCA_INSTALL_DIR_set" ]; then
        if [ ! "$DOCA_SRC_DIR" ] && [ -d "$OVS_SRC_DIR/../doca" ]; then
            DOCA_SRC_DIR="$(readlink -f $OVS_SRC_DIR/../doca)"
            vlog "Detected DOCA source: $DOCA_SRC_DIR"
        fi
        if [ -d "$DOCA_SRC_DIR" ]; then
            reflect DOCA_PREFIX
            reflect DOCA_DESC
            reflect DOCA_INSTALL_DIR
            log "DOCA source: $DOCA_SRC_DIR"
        else
            DOCA_INSTALL_DIR="/opt/mellanox/doca"
        fi
    fi
    log "DOCA installation: $DOCA_INSTALL_DIR"

    if [ ! "$NVHWS_INSTALL_DIR_set" ]; then
        if [ ! "$NVHWS_SRC_DIR" ] && [ -d "$OVS_SRC_DIR/../nv_hws" ]; then
            NVHWS_SRC_DIR="$(readlink -f $OVS_SRC_DIR/../nv_hws)"
            vlog "Detected nv_hws source: $NVHWS_SRC_DIR"
        fi
        if [ -d "$NVHWS_SRC_DIR" ]; then
            reflect NVHWS_PREFIX
            reflect NVHWS_DESC
            reflect NVHWS_INSTALL_DIR
            log "nv_hws source: $NVHWS_SRC_DIR"
            log "nv_hws installation: $NVHWS_INSTALL_DIR"
        else
            NVHWS_INSTALL_DIR=
        fi
    fi

    if [ ! "$RDMA_CORE_INSTALL_DIR_set" ]; then
        if [ ! "$RDMA_CORE_SRC_DIR" ] && [ -d "$OVS_SRC_DIR/../rdma-core" ]; then
            RDMA_CORE_SRC_DIR="$(readlink -f $OVS_SRC_DIR/../rdma-core)"
            vlog "Detected rdma-core source: $RDMA_CORE_SRC_DIR"
        fi
        if [ -d "$RDMA_CORE_SRC_DIR" ]; then
            reflect RDMA_CORE_PREFIX
            reflect RDMA_CORE_DESC
            reflect RDMA_CORE_INSTALL_DIR
            log "rdma-core source: $RDMA_CORE_SRC_DIR"
            log "rdma-core installation: $RDMA_CORE_INSTALL_DIR"
        else
            RDMA_CORE_INSTALL_DIR=
        fi
    fi
}

function print_help() {
    update_install_dirs
    eval "$(options_parser_generate_usage)"
    exit ${1:-0}
}

# Transforms a line of the type:
#
# <match[|match]> list of 1 or more acceptable match.
# =[pattern[|pattern]] if this option takes a parameter
# #<description>  The description to print for this option in the usage screen.
#
# into
#
#   spec='<match>';arg='=?';argspec='<pattern>';desc='<description>';\
#   longopt='--<match>';shortopt='-<short-match>';opt='<match>';\
#   var='MATCH';allopt='--<opt>';allopteq='--<opt>=*';
#
# These variables are generated once, then used to create the
# option parser and usage screen.
options_parser_opts_vars() (
    opt_regex='[a-zA-Z0-9|-]'
    vars="$(echo "$@" | sed -E \
"s_^(${opt_regex}+)(=?)(${opt_regex}*)[ ]*#[ ]*(.*)\
_spec='\1';arg='\2';argspec='\3';desc='\4';_")"
    eval "$vars"
    opt=''; l=''; s=''; IFS='|'
    for e in $spec; do
        case "${#e}" in
        1) s+="${s:+|}-$e" ;;
        *) l+="${l:+|}--$e"; : ${opt:="$e"} ;;
        esac
    done
    printf -- "$vars"
    printf -- "longopt='$l';shortopt='$s';opt='$opt';"
    printf -- "var='$(echo ${opt^^} | tr '-' '_')';"
    allopt="$l${s:+|}$s"
    printf -- "allopt='$allopt';"
    printf -- "allopteq='$(echo "$allopt" | sed 's/|/=*|/g')=*';"
)

# Parse all OPTS once into their list of variables.
options_parser_OPTS_VARS="$(IFS=$'\n'; for line in $options_parser_OPTS; do
    echo $(options_parser_opts_vars $line)
done)"

options_parser_generate_usage() {
    local max_optlen
    # Find the longest option from all.
    max_optlen=$(IFS=$'\n'; for vars in $options_parser_OPTS_VARS; do
        eval "$vars"
        echo ${#opt} $opt
        done | sort -rn | head -1 | cut -d' ' -f1)
    : $((max_optlen+=5))
    echo "cat <<END_OF_USAGE"
    echo "Usage: $(basename "$0") [OPTION...]"
    echo 'Optional arguments:'
    cat <<EOF
$(IFS=$'\n'; for vars in $options_parser_OPTS_VARS; do
        eval "$vars"
        printf -- "  %-*s %s" $max_optlen "$allopt${arg:+=ARG}" "$desc"
        [ "$argspec" ] && printf " [%s]" "$argspec"
        [ "$(eval echo \$$var)" ] && printf -- " (%s)" "$(eval echo \$$var)"
        printf "\n"
    done)
EOF
    echo "END_OF_USAGE"
}

options_parser_generate_parser() {
    cat <<EOF
    OPT_FATAL=""
    while [ \$# -gt 0 ]; do case "\$1" in
    $(IFS=$'\n'; for vars in $options_parser_OPTS_VARS; do
        eval "$vars"
        if [ "$arg" ]; then
            printf " %s) [ \"\$2\" ] || err \"Missing value\"; " "$allopt"
            printf "$var=\"\$2\"; ${var}_set=true; shift 2 ;; \n"
            printf " %s) $var=\"\${1#*=}\"; ${var}_set=true; " "$allopteq"
            printf "[ \"\$$var\" ] || err \"Missing value\"; shift ;; \n"
        else
            printf " %s) $var=true; shift ;; \n" "$allopt"
        fi
    done)
    --)
        shift ;;
    *)
        elog "Unrecognized argument: \$1"
        OPT_FATAL=true; shift
        ;;
    esac
    done
    $(IFS=$'\n'; for vars in $options_parser_OPTS_VARS; do
        eval "$vars"
        if [ "$arg" ] && [ "$argspec" ]; then
        cat <<END_OF_CHECK
    if ! fnmatch '$argspec' "\$$var"; then
        elog "Invalid parameter --$opt="\$$var". Supported values: '$(echo $argspec | tr '|' ',')'"
        OPT_FATAL=true
    fi
END_OF_CHECK
        fi
    done)
if [ "\$OPT_FATAL" ]; then
    print_help 1
fi
EOF
}

if [ "$options_parser_DEBUG" = "true" ]; then
    echo "VARS:"
    echo "$options_parser_OPTS_VARS"
    echo "PARSER:"
    options_parser_generate_parser
    echo "USAGE:"
    options_parser_generate_usage
    exit 0
fi

function parse_args() {
    eval "$(options_parser_generate_parser)"

    if [ "$ASAN" ] || [ "$ASAN_DPDK" ] || [ "$SPARSE" ]; then
        DEBUG=1
    fi

    if [ "$BUILDTYPE_set" ]; then
        BUILDTYPE_DPDK=$BUILDTYPE
        [ "$BUILDTYPE_DOCA_set" ] || BUILDTYPE_DOCA=$BUILDTYPE
        [ "$BUILDTYPE_NVHWS_set" ] || BUILDTYPE_NVHWS=$BUILDTYPE
        [ "$BUILDTYPE_RDMA_CORE_set" ] || BUILDTYPE_RDMA_CORE=$BUILDTYPE
    fi

    if [ "$BUILDTYPE_DPDK" == "debug" ] ||
       [ "$BUILDTYPE_DOCA" == "debug" ] ||
       [ "$BUILDTYPE_NVHWS" == "debug" ] ||
       [ "$BUILDTYPE_RDMA_CORE" == "debug" ]; then
        DEBUG=true
    fi

    if [ "$INFO" ]; then
        CFLAGS="$INFO_CFLAGS"
    fi

    if [ "$DEBUG" ]; then
        CFLAGS="$DEBUG_CFLAGS"
    fi

    if [ "$HELP" ]; then
        print_help
    fi

    if [ "$INSTALL_DEPS" ]; then
        install_deps
        exit $?
    fi

    if [ "$PRINT_DEPS" ]; then
        print_deps
        exit 0
    fi
}

function main() {
    update_install_dirs

    rebuild_dpdk
    update_dpdk_pkgconfig

    rebuild_rdma_core
    update_rdma_core_pkgconfig

    rebuild_nv_hws
    update_nv_hws_pkgconfig

    rebuild_doca
    update_doca_pkgconfig

    rebuild_openvswitch
}

parse_args "$@"
main
