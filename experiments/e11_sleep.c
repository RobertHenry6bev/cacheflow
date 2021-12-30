#include <unistd.h>
#include <stdio.h>

int main(int argc, const char **argv) {
  int secs = 100;
  printf("Sleep %d seconds\n", secs);
  sleep(secs);
  return 0;
}
