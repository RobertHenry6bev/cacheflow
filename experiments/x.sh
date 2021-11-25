#! /bin/bash
set -eu

pkill e11_flood.x || true
make e11_flood.x snapshot.x
rm -f data/* || true

if true ; then
  ./e11_flood.x &
  printf "%4d 0x%04x\n" $! $!

  ./e11_flood.x &
  printf "%4d 0x%04x\n" $! $!

  # ./e11_flood.x &
  # printf "%4d 0x%04x\n" $! $!

  sleep 1
fi

make PERIOD=50 run
