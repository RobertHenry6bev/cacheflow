.PHONY: all
all: run

#
# Usage: ./snapshot.x [-rmafi] [-o outpath] [-p period_ms] "benchmark 1", ..., "benchmark n"
# Options:
# -r	Set real-time priorities. Parent has highest priority,
#   	the priority of the benchmarks is set in decreasing order.
# -m	Mimic only. No cache snapshotting but do everything else.
# -a	Asynchrnonous mode. Do not send SIGTOP/SIGCONT to benchmarks.
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
VICTIM = e11_flood.x
run: snapshot.x $(VICTIM) | data
	lsmod | grep dumpcache || echo "dumpcache module not loaded" || false
	sudo ./snapshot.x -p $(PERIOD) -f -o data $(PWD)/$(VICTIM)
	sudo chown $(USER):$(USER) data/*

data:
	mkdir -p $@

CFLAGS = -O2 -g -Wall

snapshot.x: snapshot.c Makefile ../cache_operations.c ../params_kernel.h
	gcc $(CFLAGS) -o $@ $< -lrt

%.x: %.c Makefile
	gcc $(CFLAGS) -o $@ $< -lrt -lpthread

.PHONY: clean
clean:
	rm -f *.o *.x *.mp4 *.png *.mkv
	rm -f data/*

MAX_FILES = 50
MAX_FILES = 5000
ALL_CSV := $(shell ls data/*.csv | head -$(MAX_FILES))
ALL_PNG = $(ALL_CSV:%.csv=%.png)

DURATION_NUM=10
DURATION_DEN=1

#
# From https://superuser.com/questions/249101/how-can-i-combine-30-000-images-into-a-timelapse-movie
#
.PHONY: movie_all
movie_all: out.mp4
out.mp4: /usr/bin/ffmpeg $(ALL_PNG) Makefile
	-rm -f $@
	ffmpeg \
          -f image2 \
          -r ${DURATION_NUM}/${DURATION_DEN} \
          -i data/cachedump%04d.png \
          -pix_fmt yuv420p \
          -vf scale=16:128 \
          -loglevel quiet \
          $@

.PHONY: png_all
png_all: $(ALL_PNG) Makefile

# WATCHOUT: this consumes a lot of space
/usr/bin/ffmpeg:
	sudo apt-get install ffmpeg
/usr/bin/mencoder:
	sudo apt-get install mencoder

.PHONY: plot_insn
plot_insn: data/cachedump0012.png

SCALE = 16
data/%.png: data/%.csv plot_insn.py Makefile
	python3 plot_insn.py \
          --scale $(SCALE) \
          --output $@ \
          --maxrows=384 \
          --hit_only \
          $<

.PHONY: pylint
pylint: /usr/bin/pylint3 *.py
	/usr/bin/pylint3 *.py
/usr/bin/pylint3:
	sudo apt-get install pylint3
