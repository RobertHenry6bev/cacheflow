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
ls -l /lib/firmware/5.4.0-1045-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb
ls -l /boot/firmware/bcm2711-rpi-4-b.dtb
ls -l original.dtb

dtc -I dtb -O dts -o original.dts /lib/firmware/5.4.0-1045-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb

dtc -I dtb -O dts -o overlay_map.dts /boot/firmware/overlay_map.dtb

#
# Human edits new.dts
#
dtc -I dts -O dtb -o new.dtb new.dts
sudo cp -p new.dtb /boot/firmware/bcm2711-rpi-4-b.dtb  || true  # there will be permission errors

#
# Check if compile/decompile yields a fixpoint (it should, modulo spacing and comments in the original text)
#
dtc -I dtb -O dts -o new.decompile.out /boot/firmware/bcm2711-rpi-4-b.dtb
diff new.dts new.decompile.out
echo "no diffs"

exit 0
