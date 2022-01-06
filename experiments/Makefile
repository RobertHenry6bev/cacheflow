.PHONY: all
all: run

WHICH_CACHE = 2
WHICH_CACHE = 1

PERIOD = 5
PERIOD = 500
PERIOD = 50
PERIOD = 500

VICTIM = e10_benchmark.x
VICTIM_ARG =

VICTIM = e11_sleep.x
VICTIM_ARG = 10

VICTIM = e11_math.x
VICTIM_ARG = 500

# 120000 is about 2 seconds
VICTIM = e11_flood.x
VICTIM_ARG = 8000
VICTIM_ARG = 80000
VICTIM_ARG = 120000
VICTIM_ARG = 1200000

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
          "$(PWD)/$(VICTIM) $(VICTIM_ARG)"
	sudo chown $(USER):$(USER) data/*

data:
	mkdir -p $@

CFLAGS = -O2 -g -Wall

LINK_ARGS = -fpie
LINK_ARGS = -fno-pie
LINK_ARGS = -static

snapshot.x: snapshot.c Makefile ../cache_operations.c ../params_kernel.h
	g++ -std=c++20 $(CFLAGS) -o $@ $< -lrt $(LINK_ARGS)

%.x: %.c Makefile
	g++ -std=c++20 $(CFLAGS) -o $@ $< -lrt -lpthread $(LINK_ARGS)

%.objdump: %.x
	objdump --disassemble $< > $@

.PHONY: clean
clean:
	rm -f *.o *.x *.mp4 *.png *.mkv
	rm -f data/*
	rm -f __pycache__

CANON_CSV_FILE = ./data/cachedump0030.csv
MAX_FILES = 50
MAX_FILES = 5000
ALL_CSV := $(shell ls data/*.csv                | head -$(MAX_FILES))
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

.PHONY: all_png
all_png: png_all
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
          --kind L$(WHICH_CACHE) \
          --scale $(PNG_SCALE) \
          --show_pid \
          --stats \
          --output $@ \
          $<

data/all.png.T: data/*.csv plot_insn.py Makefile
	python3 plot_insn.py \
          --kind L$(WHICH_CACHE) \
          --scale $(PNG_SCALE) \
          --show_pid \
          --stats \
          data/*.csv
	touch $@

.PHONY: debug_line_stats
debug_line_stats: $(CANON_CSV_FILE) plot_insn.py Makefile
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

lint: $(CPPLINT) *.c *.h
	python3 $(CPPLINT) $(CPPLINT_ARGS) *.c *.h

workingsets.csv: analyze_processes.py data/*.csv
	python3 analyze_processes.py data/*.csv > $@

workingsets.png: workingsets.csv plot_workingsets.py
	python3 plot_workingsets.py --input $< --output $@
	ls -l *.png
	file *.png
