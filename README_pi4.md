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

# Set up USD (micro SD) card
Do this work on your development Linux workstation.

Download a ubuntu disk image file as necessary for running on a Raspberry Pi

For Ubuntu 18.04 (needed to run the original version of dumpcache),
visit [here](https://cdimage.ubuntu.com/releases/18.04/release/)
and download:
```bash
wget https://cdimage.ubuntu.com/releases/18.04/release/ubuntu-18.04.5-preinstalled-server-arm64+raspi4.img.xz
```

For ubuntu 20.04.3
```bash
wget https://cdimage.ubuntu.com/releases/20.04/release/ubuntu-20.04.3-preinstalled-server-arm64+raspi.img.xz

```

For ubuntu 21.04
```bash
wget https://cdimage.ubuntu.com/releases/21.04/release/ubuntu-21.04-preinstalled-server-arm64+raspi.img.xz
```

For ubuntu 21.10,
visit [here](https://ubuntu.com/download/raspberry-pi)
and download the server image (you can use the top if you want,
but there's more bloat)
```bash
wget https://cdimage.ubuntu.com/releases/21.10/release/ubuntu-21.10-preinstalled-server-arm64+raspi.img.xz
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
Select the Storage kind and do the "WRITE" operation;
the storage kind selector is probably a list of things;
do NOT be confused by the icons!  Look for the icon and name
that is for the uSD drive you probably inserted on the USB bus.

# Bringup
Unmount the uSD card from the host machine.

Turn the Raspberry pi off, aove the uSD card to the slot on the Pi 4.
Plug in keyboard, monitor, ethernet and power.

Power on.  You're up and running.

login as `ubuntu` passwd `ubuntu`.  Immediately change the password.
(robhenry's board used robhenry's normal msft passwd.)

Wait for unattended upgrade to finish in the background;
this might take as much as 30 minutes.
When top shows no more dpkg like programs burning cycles, then try to do this:

Install the first round of packages:
``` bash
sudo apt-get install --yes net-tools build-essential gdb locate universal-ctags
```

Set up your ssh environment, for a suitable host name `HOME_MACHINE`:
``` bash
scp -r -p $HOME_MACHINE:.ssh x
rm -rf .ssh
mv x .ssh
eval `ssh-agent`; ssh-add ~/.ssh/id_rsa
```

Set up your git environment, something like:
```bash
git config --global user.name "YOUR NAME HERE"
git config --global user.email "YOUR EMAIL HERE"
git config --global push.default nothing
git config --global core.editor $(which vim)
git config --global core.excludesfile ~/.gitignore_global
git config --global  merge.renamelimit 2000
git config pull.rebase false # merge (the default strategy)
```

Figure out the board's ip address so you can ssh into it from
another machine that might be more comfortable:
``` bash
ipconfig
```

# Edit boot configuration files
You'll need to carve out some amount of memory at the top end
of the physical address space.

## For a 4GByte Raspberry pi4, running ubuntu 18.04, kernel 5.4.0
```
sudo vi /boot/firmware/usercfg.txt
append to file: total_mem=3968M

# insensitive to btcmd.txt
# you can probably skip this
sudo vi /boot/firmware/btcmd.txt
append to line:  mem=3968M

# insensitive to nobtcmd.txt (only changes to a small reserved block)
# you can probably skip this
sudo vi /boot/firmware/nobtcmd.txt
append to line: mem=3968M
```

## For a 4GByte Raspberry pi4, running ubuntu 20.04, kernel 5.4.0
Confirmed on 27Dec2021
```
sudo vi /boot/firmware/cmdline.txt
append to line: mem=3968M
sudo vi /boot/firmware/usercfg.txt
append to file: total_mem=3968M
```

## For a 4GByte Raspberry pi4, running ubuntu 21.04, kernel 5.11.0
Confirmed on 27Dec2021.
```bash
sudo vi /boot/firmware/cmdline.txt
append to line: mem=3968M
sudo vi /boot/firmware/config.txt
append to file: total_mem=3968M
```

## For a 4GByte Raspberry pi4, running ubuntu 21.10
Confirmed on 28Dec2021.
```bash
sudo vi /boot/firmware/cmdline.txt
append to line: mem=3968M
sudo vi /boot/firmware/config.txt
append to file: total_mem=3968M
```

## Kernel configuration
Turn off address space layout randomization (aslr).
To do so, (re)edit `/boot/firmware/cmdline.txt`:
```bash
sudo vi /boot/firmware/cmdline.txt
# append to line: nokaslr norandmaps

sudo vi /etc/sysctl.conf
# append to file:
kernel.kptr_restrict=0
kernel.perf_event_paranoid=-1
kernel.randomize_va_space=0
```

# work area
```
Tue Dec 28 03:01:18 PM PST 2021

Unable to handle kernel paging request
at virtual address 0xfffffc0003ec0008LL

from rmap_walk_locked+0x18
phys_to_pid+0xc8

__buf_start2=0xffff800014000000
       aka 0x00ffff800014000000


calling phys_to_page with 0xfb000140

```
