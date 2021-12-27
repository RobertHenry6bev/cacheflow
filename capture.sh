#! /bin/bash

#
# capture configuration files and observed configuration changes
#

set -ux
dstdir=baseline.20.04
mkdir -p $dstdir
sudo cp /proc/iomem $dstdir
     cp /boot/firmware/btcmd.txt $dstdir
     cp /boot/firmware/nobtcmd.txt $dstdir
     cp /boot/firmware/usercfg.txt $dstdir
     cp /etc/lsb-release $dstdir
     uname -a > $dstdir/uname-a
sudo chown $USER:$USER $dstdir/*
sudo chmod oug-w       $dstdir/*

git add $dstdir
git add $dstdir/*
