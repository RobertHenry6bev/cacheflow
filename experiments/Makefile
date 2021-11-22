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

.PHONY: run
VICTIM = e10_benchmark.x
VICTIM = e11_flood.x
run: snapshot.x $(VICTIM) | data
	lsmod | grep dumpcache || echo "dumpcache module not loaded" || false
	sudo ./snapshot.x -f -o data $(PWD)/$(VICTIM)
	sudo chown $(USER):$(USER) data/*

data:
	mkdir -p $@

CFLAGS = -O0 -g -Wall

snapshot.x: snapshot.c Makefile ../cache_operations.c ../params_kernel.h
	gcc $(CFLAGS) -o $@ $< -lrt

%.x: %.c Makefile
	gcc $(CFLAGS) -o $@ $< -lrt -lpthread


.PHONY: clean
clean:
	rm -f *.o *.x *.mp4 *.png *.mkv

ALL_CSV := $(shell ls data/*.csv | head -50)
ALL_PNG = $(ALL_CSV:%.csv=%.png)

.PHONY: png_all
png_all: $(ALL_PNG) Makefile
	tar czf png_capture.tgz $(ALL_PNG)
	scp png_capture.tgz robhenry@qtm-ubnt-02:Downloads

DURATION_NUM=10
DURATION_DEN=1

.PHONY: movie_all
movie_all: out_new.mkv
out_new.mkv: /usr/bin/mencoder $(ALL_PNG)
	-rm -f $@
	mencoder \
          data/*.png -mf fps=2:type=png \
          -ovc copy \
          -o $@

.PHONY: display_movie
display_movie: out_new.mkv /usr/bin/vlc
	/usr/bin/vlc $<

#
# From https://superuser.com/questions/249101/how-can-i-combine-30-000-images-into-a-timelapse-movie
#
.PHONY: old_movie_all
old_movie_all: out.mp4
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

	scp $@ robhenry@qtm-ubnt-02:Downloads
#          -s:v -xx:128 \
#          -codec:v copy \

# WATCHOUT: this consumes a lot of space
/usr/bin/ffmpeg:
	sudo apt-get install ffmpeg
/usr/bin/mencoder:
	sudo apt-get install mencoder

.PHONY: plot_insn
plot_insn: data/cachedump0012.png

SCALE = 16
data/%.png: data/%.csv plot_insn.py data/%.csv Makefile
	python3 plot_insn.py --scale $(SCALE) --output $@ --maxrows=384 $<

.PHONY: pylint
pylint: /usr/bin/pylint3 *.py
	/usr/bin/pylint3 *.py
/usr/bin/pylint3:
	sudo apt-get install pylint3
