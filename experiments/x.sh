#! /bin/bash
set -eu

pkill e11_flood.x || true
make e11_flood.x snapshot.x
rm -f data/* || true

./e11_flood.x &
printf "%4d 0x%04x\n" $! $!

./e11_flood.x &
printf "%4d 0x%04x\n" $! $!

sleep 1

make PERIOD=500 run
