#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <dlfcn.h>

int main(int argc, char **argv) {
	int i;
	int count = 4;
	if (argc >= 2) {
		count = atol(argv[1]);
	}
    for(i = 0; i < count; i++) {
        printf("euid[%i] : %i\n", i, geteuid());
        sleep(1);
    }
    return 0;
}
