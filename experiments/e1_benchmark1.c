#include "params.h"

int main() {
	char *buf;
	int i, a;
	int iterations = 0;
	buf = (char*) malloc((BASE_BUFFSIZE_MB / 2) * 1024 * 1024);
	while (iterations < (NUM_ITERATIONS * 2)) {
		// Write to 1 Mb buffer
		for (i = 0; i < (BASE_BUFFSIZE_MB / 2) * 1024 * 1024; i = i + 4) {
			buf[i]     = '\xFE';
			buf[i + 1] = '\xCA';
			buf[i + 2] = '\xEF';
			buf[i + 3] = '\xBE';
		}
		// Read from buffer
		for (i = 0; i < (BASE_BUFFSIZE_MB / 2) * 1024 * 1024; i = i + 4) {
			a = buf[i] + buf[i + 1]  + buf[i + 2] + buf[i + 3];
		}
		// usleep(1000);
		iterations++;
	}
        (void)a;
	free(buf);
	return 0;
}
