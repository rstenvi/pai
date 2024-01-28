#include <stdio.h>

void __attribute__ ((constructor)) setup(void) {
	printf("constructor was called\n");
}

