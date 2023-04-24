===========
ovs-metrics
===========

Synopsis
========

``ovs-metrics [-1] [-p <ms>] [-f] [-x] [-d]``

Description
===========

``ovs-metrics`` accesses the Open vSwitch metrics and derives statistics
from the values received.

Default operation mode is to watch over a dashboard of metrics selected
for relevance to measure packet forwarding and connection tracking performance,
along with their offloading.

Options
=======

* ``-1`` or ``--one-shot``

  One-shot mode: Read metrics once and print them on screen.

* ``-d`` or ``--debug``

  In 'follow' or 'one-shot' mode, request the metrics debug page as well.

* ``-f`` or ``--follow``

  Follow mode: read all metrics and print any change each period.

* ``-h`` or ``--help``

  Prints a brief help message to the console.

* ``-p`` or ``--period``

  Periodicity in milliseconds of the metrics accesses.
  Default is 1000 ms.

* ``--version``

  Prints version information to the console.

* ``-x`` or ``--extended``

  In 'follow' or 'one-shot' mode, request the metrics extended page as well.

* ``-w`` or ``--wait``

  In 'watch' mode, wait for traffic to start before printing metrics.
  Traffic is defined as the measured packets-per-second (PPS).

See Also
========

``ovs-appctl(8)``, ``ovs-vswitchd(8)``
