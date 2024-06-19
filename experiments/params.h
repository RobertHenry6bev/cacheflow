#ifndef __CACHEFLOW_EXPERIMENTS_PARAMS_H
#define __CACHEFLOW_EXPERIMENTS_PARAMS_H

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <sched.h>

#define __STR(x) #x
#define STR(x) __STR(x)

#define PROC_FILENAME "/proc/dumpcache"

#define SCRATCHSPACE_DIR "/tmp/dumpcache"
#define PIPENV_DIR "/home/nvidia/.local/bin/pipenv"
#define MICROSECONDS_IN_MILLISECONDS 1000
#define MILLISECONDS_BETWEEN_SAMPLES 10 * MICROSECONDS_IN_MILLISECONDS

/* SD-VBS Params */
//#define NUM_SD_VBS_BENCHMARKS 1
/* Set to 7 to run all */
//#define NUM_SD_VBS_BENCHMARKS_DATASETS 2

#define NUM_ITERATIONS 3
#define BASE_BUFFSIZE_MB 2.0

#include "../params_kernel.h"

#endif  // __CACHEFLOW_EXPERIMENTS_PARAMS_H
