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
    printf("my pid : %d\n", getpid());
	void* h = dlopen(NULL, RTLD_NOW);
	printf("h = %p\n", h);

    for(i = 0; i < 10; i++) {
        printf("euid[%i] : %i\n", i, geteuid());
        sleep(60);
    }
    return 0;
}
