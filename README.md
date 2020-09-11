# Sysrepo DHCP plugin (DT)

## Introduction

This Sysrepo plugin is responsible for bridging OpenWrt [**UCI**]() (Unified Configuration Interface) and Sysrepo/YANG datastore DHCP configuration.

## Development Setup

Setup the development environment using the provided [`setup-dev-sysrepo`](https://github.com/sartura/setup-dev-sysrepo) scripts. This will build all the necessary components and initialize a sparse OpenWrt filesystem.

Subsequent rebuilds of the plugin may be done by navigating to the plugin source directory and executing:

```
$ export SYSREPO_DIR=${HOME}/code/sysrepofs
$ cd ${SYSREPO_DIR}/repositories/plugins/dhcp

$ rm -rf ./build && mkdir ./build && cd ./build
$ cmake -DCMAKE_EXPORT_COMPILE_COMMANDS=ON \
		-DCMAKE_PREFIX_PATH=${SYSREPO_DIR} \
		-DCMAKE_INSTALL_PREFIX=${SYSREPO_DIR} \
		-DCMAKE_BUILD_TYPE=Debug \
		..
-- The C compiler identification is GNU 9.3.0
-- Check for working C compiler: /usr/bin/cc
-- Check for working C compiler: /usr/bin/cc -- works
[...]
-- Configuring done
-- Generating done
-- Build files have been written to: ${SYSREPO_DIR}/repositories/plugins/dhcp/build

$ make && make install
[...]
[ 75%] Building C object CMakeFiles/sysrepo-plugin-dt-dhcp.dir/src/utils/memory.c.o
[100%] Linking C executable sysrepo-plugin-dt-dhcp
[100%] Built target sysrepo-plugin-dt-dhcp
[100%] Built target sysrepo-plugin-dt-dhcp
Install the project...
-- Install configuration: "Debug"
-- Installing: ${SYSREPO_DIR}/bin/sysrepo-plugin-dt-dhcp
-- Set runtime path of "${SYSREPO_DIR}/bin/sysrepo-plugin-dt-dhcp" to ""

$ cd ..
```

Before using the plugin it is necessary to install relevant YANG modules. For this particular plugin, the following commands need to be invoked:

```
$ cd ${SYSREPO_DIR}/repositories/plugins/dhcp
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$ sysrepoctl -i ./yang/terastream-dhcp@2017-12-07.yang
```

## YANG Overview

The `terastream-dhcp` YANG module with the `ts-dhcp` prefix consists of the following `container`s:

* `dhcp-servers` — operational state data for the DHCP server,
* `domains` — list of domains given to the clients,
* `dhcp-clients` — operational state data for the DHCP clients,
* `dhcp-v4-leases` — DHCP IPv4 leases,
* `dhcp-v6-leases` — DHCP IPv4 leases.

## Running and Examples

This plugin is installed as the `sysrepo-plugin-dt-dhcp` binary to `${SYSREPO_DIR}/bin/` directory path. Simply invoke this binary, making sure that the environment variables are set correctly:

```
$ export LD_LIBRARY_PATH="${SYSREPO_DIR}/lib64;${SYSREPO_DIR}/lib"
$ export PATH="${SYSREPO_DIR}/bin:${PATH}"

$
```

