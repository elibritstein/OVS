# Copyright (c) 2022 NVIDIA Corporation
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

from collections import deque
import sys
import time

try:
    from prometheus_client.parser import text_string_to_metric_families
    from prometheus_client.samples import Sample
except Exception as e:
    print("ERROR: Missing python module: %s" % e.name)
    sys.exit(1)

from . import util


class MetricsReadError(Exception):
    def __init__(self, message):
        super().__init__(message)


def get_metrics_families(extended=False, debug=False):
    """
    This function queries NVS for the metrics entries.
    Extended and debug pages can be enabled.
    """
    cmd = ["ovs-appctl", "metrics/show"]

    if extended:
        cmd.append("-x")

    if debug:
        cmd.append("-d")

    ret, out, err = util.start_process(cmd)
    if ret != 0:
        raise MetricsReadError("Failed to read metrics: is OVS running?")
    return text_string_to_metric_families(out)


class MetricPoint():
    def __init__(self, name, labels, value):
        self.name = name
        self.labels = labels
        self.value = value

    def __str__(self):
        labels = self.labels
        if len(labels):
            labels = '{' + labels + '}'
        return self.name + labels + ' ' + str(self.value)


class Entry():
    def labels_to_key(self, labels):
        if labels is None:
            return ''
        return ','.join(f'{k}="{v}"' for k, v in labels.items())

    def __init__(self, sample):
        self.name = sample.name
        self.samples = dict()
        self.labels = dict()
        key = self.labels_to_key(sample.labels)
        self.samples[key] = deque()
        self.samples[key].append(sample.value)
        self.labels[key] = sample.labels

    def last(self, labels=None):
        if len(self.samples) == 1:
            for v in self.samples.values():
                return v[-1]
        key = self.labels_to_key(labels)
        return self.samples[key][-1]

    def add_sample(self, sample):
        key = self.labels_to_key(sample.labels)
        if key in self.samples:
            if len(self.samples[key]) > 3:
                self.samples[key].popleft()
        else:
            self.samples[key] = deque()
        self.samples[key].append(sample.value)

    def __iter__(self):
        for k, v in self.samples.items():
            yield MetricPoint(self.name, k, v[-1])

    def delta(self):
        for k, v in self.samples.items():
            if len(self.samples[k]) > 1 and self.samples[k][-1] != self.samples[k][-2]:
                yield MetricPoint(self.name, k, v[-1])


class MetricsDB():
    def __init__(self, extended=False, debug=False):
        self.extended = extended
        self.debug = debug

        self.last_query_duration = 0
        self.start_ts = util.time_msec()
        self.update_ts = deque()

        self.metrics = dict()
        self.query_duration_key = ''
        self.update()
        for k, v in self.metrics.items():
            if k.endswith('scrape_duration_seconds'):
                self.query_duration_key = k
                break

    def __iter__(self):
        return self.metrics.__iter__()

    def __getitem__(self, key):
        return self.metrics.__getitem__(key)

    def items(self):
        return self.metrics.items()

    def update(self):
        families = get_metrics_families(extended=self.extended, debug=self.debug)
        self.update_ts.append(util.time_msec())
        if len(self.update_ts) > 3:
            self.update_ts.popleft()

        for metric in families:
            for sample in metric.samples:
                if sample.name in self.metrics:
                    self.metrics[sample.name].add_sample(sample)
                else:
                    self.metrics[sample.name] = Entry(sample)

        if self.query_duration_key != '':
            self.last_query_duration = self.metrics[self.query_duration_key].last() * 1000

    def last_ts(self):
        return self.update_ts[-1] - self.start_ts

    def ts_delta(self):
        val = 0
        if len(self.update_ts) == 1:
            return self.last_ts()
        if len(self.update_ts) > 1:
            val = self.update_ts[-1] - self.update_ts[-2]
        return float(val)

    def delta(self):
        for _, entry in self.metrics.items():
            for point in entry.delta():
                yield point

    def wait(self, period):
        if period < self.last_query_duration:
            sys.stderr.write("Increasing period to %d ms\n" % self.last_query_duration)
            period = self.last_query_duration
        else:
            # Avoid 'drifting' away from the target period,
            # try to remain close to requested reads
            next_wake = period
            next_wake -= self.last_ts() % period
            next_wake -= self.last_query_duration
            next_wake /= 1000
            if next_wake > 0:
                time.sleep(next_wake)
        return period

