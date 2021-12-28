obj-m += dumpcache.o

.PHONY: run
run: load
	cd experiments; make run

# CFLAGS_dumpcache.o := -D_FORTIFY_SOURCE=0

UNAME_R := $(shell uname -r)
#
# NOTE: modules_install won't work when doing out of (Linux source) tree build,
# eg, when running on the raspberry pi4 ARM hardware directly.
#
.PHONY: build
build: dumpcache.ko
dumpcache.ko: dumpcache.c cache_operations.c params_kernel.h Makefile rmap_walk_func_addr.h.out
	make -C /lib/modules/$(UNAME_R)/build M=$(PWD) modules
#	make -C /lib/modules/$(UNAME_R)/build M=$(PWD)         modules_install

xxx_rmap_walk_func_addr.h.out: /boot/System.map-$(UNAME_R) Makefile
	sudo grep rmap_walk_locked $< | sed -e 's/^/0x/' -e 's/ .*/ULL/' > $@
rmap_walk_func_addr.h.out: /proc/kallsyms Makefile
	     grep rmap_walk_locked $< | sed -e 's/^/0x/' -e 's/ .*/ULL/' > $@

.PHONY: clean
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

.PHONY: load
load: dumpcache.ko
	-sudo rmmod dumpcache
	sudo insmod $<
	sudo dmesg | tail -10

.PHONY: disassemble
disassemble: cache_jig.c experiments/data/cachedump0000.csv
	gcc -g -c cache_jig.c
	echo x/4096i vals | gdb cache_jig.o

%.x: %.c
	gcc -Wall -O0 -g -o $@ $<
