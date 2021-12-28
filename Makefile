obj-m += dumpcache.o

.PHONY: run
run: load
	cd experiments; make run

# CFLAGS_dumpcache.o := -D_FORTIFY_SOURCE=0

.PHONY: build
build: dumpcache.ko
dumpcache.ko: dumpcache.c cache_operations.c params_kernel.h Makefile
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
#	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)         modules_install

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
