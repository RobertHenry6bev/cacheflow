#! /bin/bash

#
# capture configuration files and observed configuration changes
#

set -ux
dstdir=baseline.20.04
dstdir=new.20.04
dstdir=works.20.04

dstdir=baseline.21.04
dstdir=new.21.04
dstdir=works.21.04

dstdir=baseline.21.10
dstdir=new.21.10

mkdir -p $dstdir
sudo cp /proc/iomem $dstdir
     cp /boot/firmware/btcmd.txt $dstdir
     cp /boot/firmware/nobtcmd.txt $dstdir
     cp /boot/firmware/usercfg.txt $dstdir
     cp /boot/firmware/cmdline.txt $dstdir
     cp /etc/lsb-release $dstdir
     uname -a > $dstdir/uname-a
sudo chown $USER:$USER $dstdir/*
sudo chmod oug-w       $dstdir/*

git add $dstdir
git add $dstdir/*
