#! /bin/bash

set -eux

#
# decompile binary dt b files into dts files for guessing memory map overlays
#

mkdir -p dts
for file in `find /boot -type f | grep 'dtb$' ` ; do
    newname=$(echo $file | sed -e 's,.*/,,' -e 's/dtb$/dts/')
    dtc -I dtb -O dts -o dts/$newname $file
done
