.PHONY: all
all: run

#
# Usage: ./snapshot.x [-rmafi] [-o outpath] [-p period_ms] "benchmark 1", ..., "benchmark n"
# Options:
# -r	Set real-time priorities. Parent has highest priority,
#   	the priority of the benchmarks is set in decreasing order.
# -m	Mimic only. No cache snapshotting but do everything else.
# -a	Asynchronous mode. Do not send SIGTOP/SIGCONT to benchmarks.
# -f	Force output. Overwrite content of output directory.
# -i	Isolation mode. Pin parent alone on CPU 2.
# -o	Output files to custom directory instead of /tmp/dumpcache.
# -p	Set custom period between samples expressed in msec. Default is 5 msec.
# -n	Do not perform physical->virtual address translation in the kernel.
# -t	Operate in transparent mode, i.e. defer acquisition of samples to disk to the end.
# -l	Do not acquire the memory layout of the observed benchmarks.
# 

PERIOD = 5
PERIOD = 500
PERIOD = 50
.PHONY: run
VICTIM = e10_benchmark.x
VICTIM_ARG =

VICTIM = e11_flood.x
VICTIM_ARG =

VICTIM = e11_sleep.x
VICTIM_ARG = 1

run: snapshot.x $(VICTIM) | data
	lsmod | grep dumpcache || echo "dumpcache module not loaded" || false
	sudo ./snapshot.x -p $(PERIOD) -f -o $(PWD)/data "$(PWD)/$(VICTIM) $(VICTIM_ARG)"
	sudo chown $(USER):$(USER) data/*

# e11_flood.x: e11_flood.c

data:
	mkdir -p $@

CFLAGS = -O2 -g -Wall

snapshot.x: snapshot.c Makefile ../cache_operations.c ../params_kernel.h
	g++ -std=c++20 $(CFLAGS) -o $@ $< -lrt

%.x: %.c Makefile
	g++ -std=c++20 $(CFLAGS) -o $@ $< -lrt -lpthread

%.objdump: %.x
	objdump --disassemble $< > $@

.PHONY: clean
clean:
	rm -f *.o *.x *.mp4 *.png *.mkv
	rm -f data/*

MAX_FILES = 50
MAX_FILES = 5000
# ALL_CSV := $(shell ls data/*.csv                | head -$(MAX_FILES))
ALL_CSV := $(shell find data/*.csv -size 3883008c | head -$(MAX_FILES))
ALL_PNG = $(ALL_CSV:%.csv=%.png)

DURATION_NUM=10
DURATION_DEN=1

#
# From https://superuser.com/questions/249101/how-can-i-combine-30-000-images-into-a-timelapse-movie
#
.PHONY: movie
movie: data/out.mp4
data/out.mp4: /usr/bin/ffmpeg $(ALL_PNG) Makefile
	-rm -f $@
	/usr/bin/ffmpeg \
          -r 3/1 \
          -i data/cachedump%04d.png \
          -r 24 \
          -c:v libx264 \
          -pix_fmt \
          yuv420p \
          $@

.PHONY: png_all
png_all: $(ALL_PNG) Makefile

# WATCHOUT: this consumes a lot of space
/usr/bin/ffmpeg:
	sudo apt-get install ffmpeg
/usr/bin/mencoder:
	sudo apt-get install mencoder

.PHONY: plot_insn
plot_insn: data/cachedump0000.png

PNG_SCALE = 2
data/%.png: data/%.csv plot_insn.py Makefile
	python3 plot_insn.py \
          --scale $(PNG_SCALE) \
          --show_pid \
          --output $@ \
          $<
data/all.png.T: data/*.csv plot_insn.py Makefile
	python3 plot_insn.py \
          --scale $(PNG_SCALE) \
          --show_pid \
          data/*.csv
	touch $@

.PHONY: pylint
pylint: /usr/bin/pylint *.py
	/usr/bin/pylint *.py
/usr/bin/pylint:
	sudo apt-get install pylint3

CPPLINT_ARGS = \
  --filter=-runtime/int,-readability/casting,-runtime/printf \
  $(NULL)
CPPLINT = $(HOME)/rrhbuild/cpplint/cpplint.py
lint: $(CPPLINT) *.c *.h
	python3 $(CPPLINT) $(CPPLINT_ARGS) *.c *.h

workingsets.csv: analyze_processes.py data/*.csv
	python3 analyze_processes.py data/*.csv > $@

workingsets.png: plot_workingsets.py workingsets.csv
	python3 plot_workingsets.py workingsets.csv
	ls -l *.png
	file *.png
