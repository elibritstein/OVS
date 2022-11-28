===========
ovs-metrics
===========

Synopsis
========

``ovs-metrics [-w] [-p <ms>] [-x] [-d]``

Description
===========

``ovs-metrics`` accesses the Open vSwitch metrics and derives statistics
from the values received.

Options
=======

* ``-d`` or ``--debug``

  Request the metrics debug page as well.

* ``-h`` or ``--help``

  Prints a brief help message to the console.

* ``-p`` or ``--period``

  Periodicity in milliseconds of the metrics accesses.
  Default is 1000 ms.

* ``--version``

  Prints version information to the console.

* ``-w`` or ``--watch``

  Watch continuously the measures and report time derivatives.
  This mode is disabled by default.

* ``-x`` or ``--extended``

  Request the metrics extended page as well.

See Also
========

``ovs-appctl(8)``, ``ovs-vswitchd(8)``
