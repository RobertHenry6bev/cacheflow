obj-m += dumpcache.o

.PHONY: run
run: load
	cd experiments; make run

.PHONY: build
build: dumpcache.ko
dumpcache.ko: dumpcache.c dumpcache.mod.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

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
