obj-m += dumpcache.o

.PHONY: run
run: load
	cd experiments; make run

# CFLAGS_dumpcache.o := -D_FORTIFY_SOURCE=0

UNAME_R := $(shell uname -r)

FIXED_ADDRESS_FILES = \
  xxx_rmap_walk_locked_func_addr.h.out \
  rmap_walk_locked_func_addr.h.out \
  xxx_kallsyms_lookup_name_func_addr.h.out \
  kallsyms_lookup_name_func_addr.h.out \
  $(NULL)

#
# NOTE: modules_install won't work when doing out of (Linux source) tree build,
# eg, when running on the raspberry pi4 ARM hardware directly.
#
.PHONY: build
build: dumpcache.ko
dumpcache.ko: dumpcache.c cache_operations.c params_kernel.h Makefile $(FIXED_ADDRESS_FILES)
	make -C /lib/modules/$(UNAME_R)/build M=$(PWD) modules
#	make -C /lib/modules/$(UNAME_R)/build M=$(PWD)         modules_install

xxx_rmap_walk_locked_func_addr.h.out: /boot/System.map-$(UNAME_R) Makefile
	sudo grep -w rmap_walk_locked $< | sed -e 's/^/0x/' -e 's/ .*/ULL/' > $@
rmap_walk_locked_func_addr.h.out: /proc/kallsyms Makefile
	     grep -w rmap_walk_locked $< | sed -e 's/^/0x/' -e 's/ .*/ULL/' > $@

xxx_kallsyms_lookup_name_func_addr.h.out: /boot/System.map-$(UNAME_R) Makefile
	sudo grep -w kallsyms_lookup_name $< | sed -e 's/^/0x/' -e 's/ .*/ULL/' > $@
kallsyms_lookup_name_func_addr.h.out: /proc/kallsyms Makefile
	     grep -w kallsyms_lookup_name $< | sed -e 's/^/0x/' -e 's/ .*/ULL/' > $@

.PHONY: fish
fish: $(FIXED_ADDRESS_FILES)

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

CPPLINT_ARGS = \
  --filter=-runtime/int,-readability/casting,-runtime/printf \
  $(NULL)
CPPLINT = $(HOME)/rrhbuild/cpplint/cpplint.py

XLINT_VICTIMS = \
  dumpcache.c \
  params_kernel.h \
  $(NULL)
LINT_VICTIMS = \
  cache_operations.c \
  experiments/e11_flood.c \
  experiments/snapshot.c \
  $(NULL)

.PHONY: lint
lint: $(CPPLINT) $(LINT_VICTIMS)
	python3 $(CPPLINT) $(CPPLINT_ARGS) $(LINT_VICTIMS)
