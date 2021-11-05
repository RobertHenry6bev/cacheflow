#! /bin/bash

#
# manipulate device trees so we can allocate memory
# for the cacheflow buffers
#

set -eux
#
# These three dtb files should be equivalent
#
# /boot/dtbs/5.4.0-1045-raspi/bcm2711-rpi-4-b.dtb
# /boot/firmware/bcm2711-rpi-4-b.dtb
# /lib/firmware/5.4.0-1045-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb
#

ls -l /boot/dtbs/5.4.0-1045-raspi/bcm2711-rpi-4-b.dtb
ls -l /boot/firmware/bcm2711-rpi-4-b.dtb
ls -l /lib/firmware/5.4.0-1045-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb

dtc -I dtb -O dts -o installed.dts /boot/firmware/bcm2711-rpi-4-b.dtb

FLAT_DTS=bcm2711-rpi-4-b.dts
FLAT_DTB=bcm2711-rpi-4-b.dtb
if [ ! -e ${FLAT_DTS} ] ; then
  # Built from rasppi4 linux source
  scp robhenry@qtm-ubnt-02:/home/robhenry/git-work-e2/robhenry-perf/cache_contents/${FLAT_DTS} ${FLAT_DTS}
fi
dtc -I dts -O dtb -o ${FLAT_DTB} ${FLAT_DTS}
dtc -I dtb -O dts -o computed.dts ${FLAT_DTB}

