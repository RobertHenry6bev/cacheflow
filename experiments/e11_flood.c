//
// Flood the icache with straight line code.
//
#include <inttypes.h>

#include "params.h"

int foo(int i) {
  asm(".rept 4096\neor w0, w0, 2\n.endr\n");
  return i;
}

int main() {
  int iterations;
  for (iterations = 0; iterations < 200; iterations++) {
      foo(iterations);
  }
  return 0;
}
