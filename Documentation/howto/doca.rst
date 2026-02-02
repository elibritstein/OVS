..
      Licensed under the Apache License, Version 2.0 (the "License"); you may
      not use this file except in compliance with the License. You may obtain
      a copy of the License at

          http://www.apache.org/licenses/LICENSE-2.0

      Unless required by applicable law or agreed to in writing, software
      distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
      WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
      License for the specific language governing permissions and limitations
      under the License.

      Convention for heading levels in Open vSwitch documentation:

      =======  Heading 0 (reserved for the title in a document)
      -------  Heading 1
      ~~~~~~~  Heading 2
      +++++++  Heading 3
      '''''''  Heading 4

      Avoid deeper levels because they do not render well.

============================
Using Open vSwitch with DOCA
============================

This document describes how to use Open vSwitch with DOCA on NVIDIA
BlueField DPUs and ConnectX NICs.

.. important::

   Using DOCA with OVS requires building OVS with both DPDK and DOCA
   support.  For build instructions refer to :doc:`/intro/install/doca`.

Prerequisites
-------------

Enabling DOCA
~~~~~~~~~~~~~

The ``doca-init`` option must be set to ``true`` before starting
``ovs-vswitchd``.  If DOCA cannot be initialized, the process will abort::

    $ ovs-vsctl --no-wait set Open_vSwitch . other_config:doca-init=true

DOCA also requires DPDK, so ``dpdk-init`` must be enabled as well::

    $ ovs-vsctl --no-wait set Open_vSwitch . other_config:dpdk-init=true

.. note::
  Changing either value requires restarting ``ovs-vswitchd``.

DOCA initialization can be confirmed by checking the ``doca_initialized``
value::

    $ ovs-vsctl get Open_vSwitch . doca_initialized
    true

E-Switch Configuration
~~~~~~~~~~~~~~~~~~~~~~

The NIC embedded switch (E-Switch) must be set to ``switchdev`` mode.

Set the E-Switch to switchdev mode using the PF PCI address::

    $ sudo devlink dev eswitch set pci/0000:08:00.0 mode switchdev

DPDK PCI Device Probing
~~~~~~~~~~~~~~~~~~~~~~~

DPDK must not automatically probe PCI devices when using DOCA ports.  Disable
automatic probing by passing a dummy allow-list address via ``dpdk-extra``::

    $ ovs-vsctl set Open_vSwitch . \
          other_config:dpdk-extra="-a pci:0000:00:00.0"

Device Capabilities
~~~~~~~~~~~~~~~~~~~

DOCA requires ``CAP_SYS_RAWIO`` to configure the E-Switch manager.  Without
it, OVS fails to detect the ESW manager port and all DOCA ports are
non-functional.  The ``ovs-vswitchd`` process must be started with the
``--hw-rawio-access`` command line option.

On RHEL/Fedora systems, edit ``/etc/sysconfig/openvswitch``::

    OPTIONS="--ovs-vswitchd-options='--hw-rawio-access'"

On Debian/Ubuntu systems, ``ovs-vswitchd`` runs as root by default and
already has all capabilities, so this step is not required.  If running as
a non-root user, edit ``/etc/default/openvswitch-switch``::

    OVS_CTL_OPTS="--ovs-vswitchd-options='--hw-rawio-access'"

Restart ``ovs-vswitchd`` after making the change.

Ports and Bridges
-----------------

Bridges and ports are configured with ``ovs-vsctl``.  Bridges should be
created with ``datapath_type=netdev``::

    $ ovs-vsctl add-br br0 -- set bridge br0 datapath_type=netdev

DOCA ports are added by referencing the Linux network interface name of the
port representor and setting the interface type to ``doca``.  For example,
given a NIC where ``enp8s0f0`` is the E-Switch uplink and ``enp8s0f0_0``,
``enp8s0f0_1`` are VF representors::

    $ ovs-vsctl add-port br0 enp8s0f0 -- set Interface enp8s0f0 type=doca
    $ ovs-vsctl add-port br0 enp8s0f0_0 -- set Interface enp8s0f0_0 type=doca
    $ ovs-vsctl add-port br0 enp8s0f0_1 -- set Interface enp8s0f0_1 type=doca

.. important::

   The E-Switch uplink representor (e.g. ``enp8s0f0``) must be attached to
   OVS.  Without it, VF representor ports are silently non-functional.

.. important::

   DOCA ports and mlx5 DPDK ports (``type=dpdk``) cannot coexist in the
   same OVS instance.  NVIDIA NIC ports must be either all ``type=doca`` or
   all ``type=dpdk``.  Other (non-mlx5) DPDK port types and kernel ports
   are not affected by this restriction and can be used alongside DOCA ports.

Configuration Notes
-------------------

The ``other_config:flow-limit`` value is read during DOCA initialization and
cannot be changed dynamically.  Modifying ``flow-limit`` requires restarting
``ovs-vswitchd`` for the new value to take effect with DOCA::

    $ ovs-vsctl set Open_vSwitch . other_config:flow-limit=100000

Further Reading
---------------

- :doc:`/intro/install/doca` -- Build and installation instructions.
- :doc:`/intro/install/dpdk` -- DPDK build prerequisites.
- :doc:`dpdk` -- General DPDK usage with OVS.
- `NVIDIA DOCA Documentation <https://docs.nvidia.com/doca/>`_ -- Upstream
  DOCA SDK reference.
