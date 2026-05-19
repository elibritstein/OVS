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

======================
Open vSwitch with DOCA
======================

This document describes how to build and install Open vSwitch with DOCA
support on NVIDIA BlueField and ConnectX network platforms.

.. warning::
  The DOCA support of Open vSwitch is considered 'experimental'.

.. important::

   Building OVS with DOCA requires a working DPDK build first.  Refer to
   :doc:`dpdk` for DPDK build and installation instructions.

Build Requirements
------------------

In addition to the requirements described in :doc:`general` and :doc:`dpdk`,
building Open vSwitch with DOCA requires the following:

- DPDK with mlx5 PMD driver enabled (see :doc:`dpdk`).  The DOCA SDK
  includes a compatible DPDK build (``dpdk-community-dev`` on Debian/Ubuntu,
  ``dpdk-community-devel`` on RPM).  Alternatively, DPDK can be built from
  source with ``-Denable_drivers=bus/auxiliary,common/mlx5,net/mlx5``.
  net/mlx5 requires common/mlx5 which requires bus/auxiliary.

- DOCA SDK packages (Debian/Ubuntu: ``libdoca-sdk-flow-dev``,
  ``libdoca-sdk-dpdk-bridge-dev``; RPM: ``doca-sdk-flow-devel``,
  ``doca-sdk-dpdk-bridge-devel``)

- An NVIDIA BlueField DPU or ConnectX NIC with a supported firmware version

.. _doca-install:

Installing
----------

Install DOCA SDK
~~~~~~~~~~~~~~~~

The DOCA SDK can be installed from the NVIDIA package repository.

#. Download the DOCA host repo package from the `NVIDIA DOCA Downloads`_ page:

   Select *Host-Server* deployment platform, *DOCA-Host* deployment package,
   *Linux* target OS, and *x86_64* architecture.

#. Install the repository and SDK packages::

       $ sudo dpkg -i doca-repo.deb
       $ sudo apt-get update
       $ sudo apt-get install -y  \
             libdoca-sdk-flow-dev libdoca-sdk-dpdk-bridge-dev

   On RPM-based distributions::

       $ sudo rpm -i doca-repo.rpm
       $ sudo dnf install -y \
             doca-sdk-flow-devel doca-sdk-dpdk-bridge-devel

.. _NVIDIA DOCA Downloads: https://developer.nvidia.com/doca-downloads

Install OVS
~~~~~~~~~~~~

OVS must be configured with ``--with-dpdk`` and ``--with-doca``.
``--with-doca`` is a flag only. Any argument is ignored.  The link type
follows the ``--with-dpdk`` setting.

#. Ensure the standard OVS requirements, described in
   :ref:`general-build-reqs`, are installed

#. Bootstrap, if required, as described in :ref:`general-bootstrapping`

#. Configure the package with DPDK and DOCA support:

       $ ./configure --with-dpdk=static --with-doca

   .. note::
     ``--with-doca`` requires ``--with-dpdk``.  The configure step will fail
     if DPDK is not enabled.

   .. note::
     While ``--with-dpdk`` and ``--with-doca`` are required, you can pass
     any other configuration option described in :ref:`general-configuring`.

#. Build and install OVS, as described in :ref:`general-building`

Additional information can be found in :doc:`general`.

Runtime configuration
~~~~~~~~~~~~~~~~~~~~~

After installation, enabling DOCA ports requires **both**
``other_config:dpdk-init=true`` and ``other_config:doca-init=true``.
See :doc:`/howto/doca` for the full procedure and examples.
