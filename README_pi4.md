Running on Raspberry Pi 4

# Ordering
Don't cheap out.
Get as much RAM as you can afford,
and the biggest uSD card you can afford.
I've found that 4GBytes of RAM and a 32GByte uSD card are sufficient
for my work, although I've not built a kernel.

You will need to buy an approved power supply.

You should get the enclosure to protect this small computer.

You will need a microHDMI to HDMI cable.  In Redmond,
go to Vetco electronics (2 miles off campus) to buy one.

You will need a monitor that takes HDMI.
These are hard to find in Redmond MSFT campus.

# Set up usd card
Do this work on your development Linux workstation.

Download a ubuntu disk image file as necessary for running on a Raspberry Pi

For Ubuntu 18.04 (needed to run the original version of dumpcache),
visit [here](https://cdimage.ubuntu.com/releases/18.04/release/)
and download:
```bash
wget https://cdimage.ubuntu.com/releases/18.04/release/ubuntu-18.04.5-preinstalled-server-arm64+raspi4.img.xz
```

For ubuntu 21.10,
visit [here](https://ubuntu.com/download/raspberry-pi)
and download:
```bash
wget https://cdimage.ubuntu.com/releases/21.10/release/ubuntu-21.10-preinstalled-desktop-arm64+raspi.img.xz?_ga=2.64572015.1121619683.1637011980-2125342577.1636579052
```

Running on your Ubuntu devel machine,
follow the instructions at
[here](https://ubuntu.com/tutorials/how-to-install-ubuntu-desktop-on-raspberry-pi-4#1-overview)
```bash
sudo snap install rpi-imager
sudo snap install wayland --beta  # when on an ubuntu 21.10 dev machine

rpi-imager

```
Navigate to the bottom to "Use Custom",
and point rpi-imager at the img.xz file you just downloaded.
Select the Storage kind (use the one with the uSD card outline),
and do the "WRITE" operation.

# Bringup
Unmount the uSD card from the host machine.

Turn the Raspberry pi off, aove the uSD card to the slot on the Pi 4.

Power on.  you're up and running

