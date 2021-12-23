
Contents of Raspberry pi4 4Gb /proc/iomem with all memory 
configured in (eg, without changes to /boot/firmware/usercfg.txt
```
00000000-3b3fffff : System RAM
  00000000-00000fff : reserved
  00080000-013fffff : Kernel code
  01400000-017fffff : reserved
  01800000-01a4ffff : Kernel data
  02600000-0260cfff : reserved
  02700000-03c2bfff : reserved
  2c000000-2fffffff : reserved
  37400000-3b3fffff : reserved
40000000-fbffffff : System RAM
  f7000000-f77fffff : reserved
  f7806000-f7807fff : reserved
  f7920000-fb7fffff : reserved
  fb805000-fb805fff : reserved
  fb808000-fb808fff : reserved
  fb809000-fb80bfff : reserved
  fb80c000-fb80cfff : reserved
  fb80d000-fbffffff : reserved
fd500000-fd50930f : fd500000.pcie pcie@7d500000
fd580000-fd58ffff : fd580000.ethernet ethernet@7d580000
  fd580e14-fd580e1c : unimac-mdio.-19
fe007000-fe007aff : fe007000.dma dma@7e007000
fe007b00-fe007eff : fe007b00.dma dma@7e007b00
fe00a000-fe00a023 : fe100000.watchdog watchdog@7e100000
fe00b840-fe00b87b : fe00b840.mailbox mailbox@7e00b840
fe00b880-fe00b8bf : fe00b880.mailbox mailbox@7e00b880
fe100000-fe100113 : fe100000.watchdog watchdog@7e100000
fe101000-fe102fff : fe101000.cprman cprman@7e101000
fe104000-fe10400f : fe104000.rng rng@7e104000
fe200000-fe2000b3 : fe200000.gpio gpio@7e200000
fe201000-fe2011ff : serial@7e201000
  fe201000-fe2011ff : fe201000.serial serial@7e201000
fe204000-fe2041ff : fe204000.spi spi@7e204000
fe215000-fe215007 : fe215000.aux aux@7e215000
fe215040-fe21507f : fe215040.serial serial@7e215040
fe300000-fe3000ff : fe300000.mmcnr mmcnr@7e300000
fe340000-fe3400ff : fe340000.emmc2 emmc2@7e340000
fe804000-fe804fff : fe804000.i2c i2c@7e804000
fec11000-fec1101f : fe100000.watchdog watchdog@7e100000
600000000-603ffffff : pcie@7d500000
  600000000-6000fffff : PCI Bus 0000:01
    600000000-600000fff : 0000:01:00.0
      600000000-600000fff : xhci-hcd
```
