//
// Flood the icache with straight line code.
//
#include <inttypes.h>
#include <pthread.h>
#include <stdlib.h>
#include <pthread.h>

#include "params.h"

int foo(int i) {
  int iterations;
  // 30 * 1000 * 200 ==> 16 seconds
  for (iterations = 0; iterations < 30*1000*200; iterations++) {
    asm(".rept 4096\neor w0, w0, 2\n.endr\n");  // 0x521f0000
  }
  return i;
}

void *foo_runner(void *vp) {
  int i = foo(*(int *)vp);
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
