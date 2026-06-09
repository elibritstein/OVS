#! /usr/bin/env python3
# Copyright (c) 2017 Red Hat, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import getopt
import sys


def strip_policy(check_dpdk, check_doca, src, dst):
    skip_dpdk = False
    skip_doca = False
    skip_nodoca = False
    while True:
        line = src.readline()
        if not line:
            break
        if '@begin_dpdk@' in line or '@end_dpdk@' in line:
            if not check_dpdk:
                skip_dpdk = not skip_dpdk
            continue
        if '@begin_doca@' in line or '@end_doca@' in line:
            if not check_doca:
                skip_doca = not skip_doca
            continue
        if '@begin_nodoca@' in line or '@end_nodoca@' in line:
            if check_doca:
                skip_nodoca = not skip_nodoca
            continue
        if not skip_dpdk and not skip_doca and not skip_nodoca:
            dst.write(line)


if __name__ == '__main__':
    check_dpdk = False
    check_doca = False
    options, args = getopt.gnu_getopt(sys.argv[1:], '', ['dpdk', 'nodpdk',
                                                         'doca', 'nodoca'])
    for key, value in options:
        if key == '--dpdk':
            check_dpdk = True
        elif key == '--nodpdk':
            check_dpdk = False
        elif key == '--doca':
            check_doca = True
        elif key == '--nodoca':
            check_doca = False
        else:
            assert False
    if args:
        for arg in args:
            strip_policy(check_dpdk, check_doca, open(arg), sys.stdout)
    else:
        strip_policy(check_dpdk, check_doca, sys.stdin, sys.stdout)
