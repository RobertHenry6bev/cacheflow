obj-m += dumpcache.o

.PHONY: all
all: dumpcache.ko
dumpcache.ko: dumpcache.c dumpcache.mod.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY: load
load: dumpcache.ko
	-sudo rmmod dumpcache
	sudo insmod $<
	dmesg | tail -10
