#include <inttypes.h>

#include "params.h"

int main() {
	uint32_t *buf;
	uint32_t a = 0;
        size_t i;
	int iterations = 0;
        size_t nuint32_t = ((BASE_BUFFSIZE_MB / 2) * 1024 * 1024) / sizeof(uint32_t);
	buf = (uint32_t*) malloc(nuint32_t);
	while (iterations < (NUM_ITERATIONS * 2)) {
		// Write to 1 Mb buffer
                for (i = 0; i < nuint32_t; i++) {
                  buf[i] = (0xa + i) * 0x11111111UL;
                }
		// Read from buffer
                for (i = 0; i < nuint32_t; i++) {
                  a += buf[i];
                }
		// usleep(1000);
		iterations++;
	}
        (void)a;
	free(buf);
	return 0;
}
