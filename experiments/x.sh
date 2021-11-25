set -eux
make e11_flood.x

pkill e11_flood.x || true
rm -f data/* || true

./e11_flood.x &
printf "%4d 0x%04x\n" $! $!

./e11_flood.x &
printf "%4d 0x%04x\n" $! $!

make
