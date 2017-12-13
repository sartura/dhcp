SIP Sysrepo plugin.

## crosscompile with OpenWrt

```
$ mkdir build
$ cd build
$ # path to OpenWrt target toolchain
$ export STAGING_DIR=/opt/inteno/iopsys/staging_dir/target-arm_xscale_uClibc-0.9.33.2_eabi
$ export COMP=$STAGING_DIR/../toolchain-arm_xscale_gcc-4.8-linaro_uClibc-0.9.33.2_eabi
$ $STAGING_DIR/../host/bin/cmake -DCMAKE_FIND_ROOT_PATH=$STAGING_DIR --DCMAKE_LIBRARY_PATH=$STAGING_DIR -DCMAKE_C_COMPILER=$COMP/bin/arm-openwrt-linux-uclibcgnueabi-gcc -DCMAKE_C_FLAGS="-Wall -std=gnu99" -DCMAKE_BUILD_TYPE=Debug ..
$ make
```
