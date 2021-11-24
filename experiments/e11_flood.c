//
// Flood the icache with straight line code.
//
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <pthread.h>

#include "params.h"

#include "flooders.c.out"

typedef int(*foorunner)(int);
static foorunner foorunners[] = {
  foo_0x0,
  foo_0x1,
  foo_0x2,
  foo_0x3,
  foo_0x4,
  foo_0x5,
  foo_0x6,
  foo_0x7,
  foo_0x8,
  foo_0x9,
  foo_0xa,
  foo_0xb,
  foo_0xc,
  foo_0xd,
  foo_0xe,
  foo_0xf,
};

void *foo_runner(void *vp) {
  int runner_number = getpid() % 16;
  printf("runner_number=%d\n", runner_number);
  int i = foorunners[runner_number](*(int *)vp);
  (void)i;
  return NULL;
}

#define NTHREAD 4
int main() {
  int i;
  int thread_arg[NTHREAD];
  pthread_t *worker_thread = calloc(NTHREAD, sizeof(pthread_t));
  for (i = 0; i < NTHREAD; i++) {
    thread_arg[i] = i;
    pthread_create(
      &worker_thread[i],
      NULL,
      foo_runner,
      &thread_arg[i]);
  }
  // sleep(10);
  for (i = 0; i < NTHREAD; i++) {
    pthread_join(worker_thread[i], NULL);
  }
  return 0;
}
