#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <memory.h>
#include <string.h>

#define MB (1024 * 1024)

void __attribute__((noinline)) work_double(double *X, size_t N) {
   for (size_t i = 0; i < N; i++) {
     X[i] = X[N-i-1] * 27.0;
   }
}

int main(int argc, const char**argv) {
  int niters = 200;
  if (argc >= 2) {
    niters = atoi(argv[1]);
  }
  double X[(4 * MB) / sizeof(double)];
  memset(X, 0, sizeof(X));
  for (int i = 0; i < niters; i++) {
    work_double(X, sizeof(X)/sizeof(double));
  }
  return 0;
}
