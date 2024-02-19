#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

void xexit(const char* msg) {
	puts(msg);
	exit(EXIT_FAILURE);
}
void* xalloc(int sz) {
	void* ptr = malloc(sz);
	if(ptr == NULL) {
		xexit("unable to alloc memory");
	}
	return ptr;
}

static int childFunc(void *arg __attribute__((unused))) {
	puts("child: start");
	sleep(2);
	puts("child: terminate");
	return 0;
}

int main(int argc, char *argv[]) {
	pid_t *pids;
	size_t nproc, i;
	int ret = EXIT_SUCCESS;

	if (argc != 2) {
		puts("Wrong way to execute the program:\n"
			"\t\t./forkwait nProcesses\n"
			"example:\t./waitpid 2");

		return EXIT_FAILURE;
	}

	nproc = atol(argv[1]);

	pids = xalloc(nproc * sizeof(pid_t));

	for (i = 0; i < nproc; i++) {
		int pid = fork();
		if(pid == 0) {
			childFunc(NULL);
			free(pids);
			exit(0);
		} else {
			pids[i] = pid;
		}
	}

	sleep(1);

	for (i = 0; i < nproc; i++) {
		if (waitpid(pids[i], NULL, 0) == -1) {
			puts("errror on waitpid");
			ret = EXIT_FAILURE;
		} else {
			printf("child %ld has terminated\n", (long)pids[i]);
		}
	}
	free(pids);
	return ret;
}
