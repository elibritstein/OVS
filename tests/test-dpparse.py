#!/usr/bin/env python3
# Copyright (c) 2022 Red Hat, Inc.
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

"""test-dpparse reads flows from stdin and tries to parse them using
the python flow parsing library.
"""

import sys

try:
    from ovs.flow.odp import ODPFlow
except ImportError:
    ODPFlow = None


def main():
    # Read stdin entirely before validating so upstream ``sed`` in pipelines does
    # not hit SIGPIPE.  Use splitlines(keepends=True) so each line matches
    # fileinput.input() (blank lines are ``'\\n'``, not ``''``).
    lines = sys.stdin.read().splitlines(keepends=True)
    if ODPFlow is None:
        return 0

    for flow in lines:
        try:
            result_flow = ODPFlow(flow)
            if flow != str(result_flow):
                print("in: {}".format(flow))
                print("out: {}".format(str(result_flow)))
                raise ValueError("Flow conversion back to string failed")
        except Exception as e:
            print("Error parsing flow {}: {}".format(flow, e))
            return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
