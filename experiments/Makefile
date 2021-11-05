.PHONY: all
all: clean e1_benchmark.x e1_benchmark1.x e1_benchmark2.x e2_benchmark.x snapshot.x
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
run: snapshot.x e1_benchmark.x | data
	lsmod | grep dumpcache || echo "dumpcache module not loaded" || false
	sudo ./snapshot.x -n -m -f -o data $(PWD)/e1_benchmark.x
data:
	mkdir -p $@

CFLAGS = -O0 -g -Wall

snapshot.x: snapshot.c Makefile
	gcc $(CFLAGS) -o $@ $< -lrt

e1_benchmark.x: e1_benchmark.c Makefile
	gcc $(CFLAGS) -o $@ $< -lrt

e1_benchmark1.x: e1_benchmark1.c Makefile
	gcc $(CFLAGS) -o $@ $< -lrt

e1_benchmark2.x: e1_benchmark2.c Makefile
	gcc $(CFLAGS) -o $@ $< -lrt

e2_benchmark.x: e2_benchmark.c Makefile
	gcc $(CFLAGS) -o $@ $< -lrt

.PHONY: clean
clean:
	rm -f *.o *.x

