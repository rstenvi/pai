#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
	int count = 10, i;
	if(argc > 1) {
		count = atoi(argv[1]);
	}
    for(i = 0; i < count; i++) {
        printf("pid[%i] : %i\n", i, getpid());
        usleep(1000 * 10);
    }
    return 0;
}
