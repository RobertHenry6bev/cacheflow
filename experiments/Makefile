NULL =
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

UNAME_M := $(shell uname -m)

#
# Choose between L1 or L2 cache
#
WHICH_CACHE = 1
WHICH_CACHE = 2

#
# Dumping L2 cache takes 316msecs/sample....
# Asking for shorter periods is counter-productive?
#
PERIOD = 5
PERIOD = 500
PERIOD = 50
PERIOD = 10

VICTIM = e10_benchmark.x
VICTIM_ARGS =

VICTIM = e11_math.x
VICTIM_ARGS = 500

VICTIM = e11_sleep.x
VICTIM_ARGS = 20


# 120000 is about 2 seconds on Raspberry Pi4 
VICTIM = e11_flood.x
# Args are: number_of_pages, number_executions_over_pages
VICTIM_ARGS = 10 8000
VICTIM_ARGS = 10 80000
VICTIM_ARGS = 10 120000
VICTIM_ARGS = 10 1200000

# VICTIM = e11_flood.x
# VICTIM_ARGS = 2 1

ifeq ($(UNAME_M),aarch64)
  GXX = /usr/bin/g++
else
  GXX = /usr/bin/aarch64-linux-gnu-g++-9
endif

.PHONY: run
run: snapshot.x $(VICTIM) | data
	lsmod | grep dumpcache || echo "dumpcache module not loaded" || false
	sudo \
          /usr/bin/taskset --cpu-list 2 \
          ./snapshot.x \
          -l \
          -$(WHICH_CACHE) \
          -p $(PERIOD) \
          -f \
          -o $(PWD)/data \
          "$(PWD)/$(VICTIM) $(VICTIM_ARGS)"
	sudo chown $(USER):$(USER) data/*

data:
	mkdir -p $@

CFLAGS = -O2 -g -Wall

LINK_ARGS = -fpie
LINK_ARGS = -fno-pie
LINK_ARGS = -static

DO_NATIVE=yes
ifeq ($(DO_NATIVE),yes)
  GXX     = /usr/bin/g++-10
  OBJDUMP = /usr/bin/objdump
else
  GXX     = /usr/bin/aarch64-linux-gnu-g++-10
  OBJDUMP = /usr/bin/aarch64-linux-gnu-objdump
endif

snapshot.x: snapshot.c ../cache_operations.c ../params_kernel.h $(GXX)
	$(GXX) -std=c++20 $(CFLAGS) -o $@ $< -lrt $(LINK_ARGS)

%.x: %.c $(GXX)
	$(GXX) -std=c++20 $(CFLAGS) -o $@ $< -lrt -lpthread $(LINK_ARGS)

%.objdump: %.x $(OBJDUMP)
	$(OBJDUMP) --disassemble $< > $@

.PHONY: clean
clean:
	rm -f *.o *.x *.mp4 *.png *.mkv
	rm -f data/*
	rm -f __pycache__

CANON_CSV_FILE = ./data/cachedump0030.csv
MAX_FILES = 50
MAX_FILES = 5000
ALL_CSV := $(shell ls data/*.$(WHICH_CACHE).*csv                | head -$(MAX_FILES))
ALL_PNG = $(ALL_CSV:%.csv=%.png)

DURATION_NUM=10
DURATION_DEN=1

#
# From https://superuser.com/questions/249101/how-can-i-combine-30-000-images-into-a-timelapse-movie
#
.PHONY: movie
movie: data/out.mp4
data/out.mp4: /usr/bin/ffmpeg $(ALL_PNG)
	-rm -f $@
	/usr/bin/ffmpeg \
          -r 3/1 \
          -i data/cachedump%04d.png \
          -r 24 \
          -c:v libx264 \
          -pix_fmt \
          yuv420p \
          $@

.PHONY: all_png
all_png: png_all
.PHONY: png_all
png_all: $(ALL_PNG)

# WATCHOUT: this consumes a lot of space
/usr/bin/ffmpeg:
	sudo apt-get install ffmpeg
/usr/bin/mencoder:
	sudo apt-get install mencoder

.PHONY: plot_insn
plot_insn: data/cachedump0000.png

PNG_SCALE = 2
data/%.png: data/%.csv plot_insn.py
	python3 plot_insn.py \
          --kind L$(WHICH_CACHE) \
          --scale $(PNG_SCALE) \
          --show_pid \
          --stats \
          --output $@ \
          $<

data/all.png.T: data/*.$(WHICH_CACHE).*.csv plot_insn.py
	python3 plot_insn.py \
          --kind L$(WHICH_CACHE) \
          --scale $(PNG_SCALE) \
          --show_pid \
          --stats \
          data/*.$(WHICH_CACHE).*.csv
	touch $@

.PHONY: line_stats
line_stats: $(CANON_CSV_FILE) plot_insn.py
	python3 plot_insn.py \
          --kind L$(WHICH_CACHE) \
          --scale $(PNG_SCALE) \
          --show_pid \
          --stats \
          --output junk.png \
          $(ALL_CSV)

.PHONY: pylint
pylint: /usr/bin/pylint *.py
	/usr/bin/pylint *.py
/usr/bin/pylint:
	sudo apt-get install pylint3

CPPLINT_ARGS = \
  --filter=-runtime/int,-readability/casting,-runtime/printf \
  $(NULL)
CPPLINT = $(HOME)/rrhbuild/cpplint/cpplint.py

CAPSTONE = capstone.T

lint: $(CPPLINT) *.c *.h $(CAPSTONE)
	python3 $(CPPLINT) $(CPPLINT_ARGS) *.c *.h

.PRECIOUS: %.csv %.png
workingsets.csv: analyze_processes.py data/cachedump.$(WHICH_CACHE).*.csv $(CAPSTONE)
	python3 analyze_processes.py \
          --kind L$(WHICH_CACHE) \
          data/cachedump.$(WHICH_CACHE).*.csv \
          > $@

workingsets.data.png workingsets.code.png: workingsets.csv plot_workingsets.py
	python3 plot_workingsets.py \
          --period $(PERIOD) \
          --kind L$(WHICH_CACHE) \
          --input $< \
          --output workingsets.%s.png
	ls -l *.png
	file *.png

$(CAPSTONE): /usr/bin/pip3
	/usr/bin/pip3 install capstone
	touch $@
/usr/bin/pip3:
	sudo apt-get install --yes python3-pip
