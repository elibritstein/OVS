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

On failure, writes debug files in the current working directory (the test's
testsuite.dir subdirectory). These are not registered with AT_CAPTURE_FILE;
on failure inspect the test directory (nothing extra is collected on success):
  test-dpparse.failure-summary.txt   - line number, source path, lengths, diff
  test-dpparse.failure.traceback.txt - exception traceback (parse errors only)
  test-dpparse.failure-input.txt     - exact failing line as read from input
"""

import fileinput
import os
import sys
import traceback

_DEBUG_FILES = (
    "test-dpparse.failure-summary.txt",
    "test-dpparse.failure.traceback.txt",
    "test-dpparse.failure-input.txt",
)

try:
    from ovs.flow.odp import ODPFlow
except ImportError:
    sys.exit(0)


def _remove_prior_debug_artifacts():
    for name in _DEBUG_FILES:
        try:
            os.unlink(name)
        except OSError:
            pass


def _truncate(s, limit):
    if len(s) <= limit:
        return s
    omitted = len(s) - limit
    return s[:limit] + "\n... [{} characters truncated] ...\n".format(omitted)


def _first_string_diff(a, b):
    """Return (index, repr_a, repr_b) for first differing index, or None."""
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i, repr(a[i]), repr(b[i])
    if len(a) != len(b):
        if len(a) > len(b):
            return len(b), repr(a[len(b)]), "(end of shorter output)"
        return len(a), "(end of shorter input)", repr(b[len(a)])
    return None


def _write_failure_input(flow):
    with open(_DEBUG_FILES[2], "wb") as f:
        f.write(flow.encode("utf-8"))


def _write_traceback(exc_type, exc, tb):
    with open(_DEBUG_FILES[1], "w", encoding="utf-8") as f:
        traceback.print_exception(exc_type, exc, tb, file=f)


def _write_summary(parts):
    with open(_DEBUG_FILES[0], "w", encoding="utf-8") as f:
        f.write("test-dpparse failure diagnostics\n")
        f.write("================================\n")
        f.write("cwd: {}\n".format(os.getcwd()))
        f.write("python: {}\n".format(sys.version.replace("\n", " ")))
        for title, body in parts:
            f.write("\n--- {} ---\n".format(title))
            if body is None:
                continue
            if not body.endswith("\n"):
                f.write(body)
                f.write("\n")
            else:
                f.write(body)


def _fail_parse(line_no, flow, source_file, exc_type, exc, tb):
    print("Error parsing flow {}: {}".format(flow, exc))
    parts = [
        ("line_number", str(line_no)),
        ("input_source", source_file or "(stdin)"),
        ("flow_byte_length", str(len(flow.encode("utf-8")))),
        ("flow_char_length", str(len(flow))),
        ("flow_repr_truncated", repr(_truncate(flow, 4000))),
        ("exception", "{}: {}".format(exc_type.__name__, exc)),
    ]
    _write_summary(parts)
    _write_failure_input(flow)
    _write_traceback(exc_type, exc, tb)
    return 1


def _fail_roundtrip(line_no, flow, source_file, out_s):
    print("in: {}".format(flow))
    print("out: {}".format(out_s))
    diff = _first_string_diff(flow, out_s)
    diff_txt = None
    if diff is not None:
        idx, ca, cb = diff
        lo = max(0, idx - 40)
        hi = idx + 40
        ctx_in = _truncate(flow[lo:hi], 500)
        ctx_out = _truncate(out_s[lo:hi], 500)
        diff_txt = (
            "first_difference_index: {}\n"
            "in_char: {}\n"
            "out_char: {}\n"
            "context_in: {!r}\n"
            "context_out: {!r}".format(idx, ca, cb, ctx_in, ctx_out)
        )
    parts = [
        ("line_number", str(line_no)),
        ("input_source", source_file or "(stdin)"),
        ("failure_kind", "round-trip string mismatch after successful parse"),
        ("in_char_length", str(len(flow))),
        ("out_char_length", str(len(out_s))),
        ("in_byte_length", str(len(flow.encode("utf-8")))),
        ("out_byte_length", str(len(out_s.encode("utf-8")))),
        ("in_repr_truncated", repr(_truncate(flow, 4000))),
        ("out_repr_truncated", repr(_truncate(out_s, 4000))),
        ("first_difference", diff_txt),
    ]
    _write_summary(parts)
    _write_failure_input(flow)
    try:
        os.unlink(_DEBUG_FILES[1])
    except OSError:
        pass
    return 1


def main():
    _remove_prior_debug_artifacts()
    for line_no, flow in enumerate(fileinput.input(), start=1):
        source_file = fileinput.filename()
        try:
            result_flow = ODPFlow(flow)
            out_s = str(result_flow)
            if flow != out_s:
                return _fail_roundtrip(line_no, flow, source_file, out_s)
        except Exception:
            return _fail_parse(
                line_no,
                flow,
                source_file,
                *sys.exc_info(),
            )
    return 0


if __name__ == "__main__":
    sys.exit(main())
