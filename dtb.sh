#! /bin/bash

#
# manipulate device trees so we can allocate memory
# for the cacheflow buffers
#

set -eux
#
# Kernel 5.4.0:
# These three dtb files should be equivalent
#   /boot/dtbs/5.4.0-1045-raspi/bcm2711-rpi-4-b.dtb
#   /boot/firmware/bcm2711-rpi-4-b.dtb
#   /lib/firmware/5.4.0-1045-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb
#
# Kernel 5.13.0-1008-raspi ubuntu 21.10
# These two dtb files should be equivalent
#
# /boot/firmware/bcm2711-rpi-4-b.dtb
# /usr/lib/firmware/5.13.0-1008-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb

# OS=5.4.0-1045
# FILE0=/boot/dtbs/${OS}-raspi/bcm2711-rpi-4-b.dtb
# FILE1=/usr/lib/firmware/${OS}-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb

OS=5.13.0-1008
FILE0=/boot/firmware/bcm2711-rpi-4-b.dtb
FILE1=/usr/lib/firmware/${OS}-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb

ls -l $FILE0 $FILE1
sum   $FILE0 $FILE1

dtc -I dtb -O dts -o original.dts $FILE1

if [ ! -e new.dts ] ; then
  cp original.dts new.dts
fi

#
# Human edits new.dts
# No changes expected,
# so nothing written back to the
#
exit

dtc -I dts -O dtb -o new.dtb new.dts
sudo cp -p new.dtb ${FILE0}  || true  # there will be permission errors

#
# Check if compile/decompile yields a fixpoint (it should, modulo spacing and comments in the original text)
#
dtc -I dtb -O dts -o new.decompile.out /boot/firmware/bcm2711-rpi-4-b.dtb
diff new.dts new.decompile.out
echo "no diffs"

exit 0
