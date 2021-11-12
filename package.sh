#! /bin/bash

#
# gather files to ship to collaborators
#

sudo cat /proc/iomem > iomem.new.out
uname -a > uname.out
cat /etc/lsb* > release.out
sudo dmesg > dmesg.out
grep -e '-' README.md > iomem.original.out
ls -l /lib/firmware/5.4.0-1045-raspi/device-tree/broadcom/bcm2711-rpi-4-b.dtb > ls.out

tar czf robhenry.01.tar.gz *.out *.dts
