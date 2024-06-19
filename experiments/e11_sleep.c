#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, const char **argv) {
  int secs = 100;
  if (argc >= 2) {
     secs = atoi(argv[1]);
  }
  printf("Sleep %d seconds\n", secs);
  if (secs >= 0) {
      sleep(secs);
  }
  return 0;
}
