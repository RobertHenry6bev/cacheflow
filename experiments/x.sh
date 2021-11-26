#! /bin/bash
set -eu

pkill e11_flood.x || true
make e11_flood.x snapshot.x
rm -f data/* || true

if true ; then
  for ((i=0;i<0;i++)) ; do
    ./e11_flood.x &
    printf "%4d 0x%04x\n" $! $!
  done
  sleep 1
fi

make PERIOD=10 run
