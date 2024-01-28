#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define STACK_SIZE (1024 * 1024) /* Stack size for cloned child */
#define ERREXIT(msg)                                                           \
  {                                                                            \
    perror(msg);                                                               \
    exit(EXIT_FAILURE);                                                        \
  }
#define CHECKALLOC(ptr, msg)                                                   \
  ({                                                                           \
    void *p = ptr;                                                             \
    if (p == NULL)                                                             \
      ERREXIT(msg);                                                            \
    p;                                                                         \
  })

static int
childFunc(void *arg __attribute__((unused)))
{
  puts("child: start");
  sleep(2);
  puts("child: terminate");
  return 0; /* Child terminates now */
}

int
main(int argc, char *argv[])
{
  pid_t *pids;   /* Child process's pids */
  size_t nproc, i;

  if (argc != 2) {
    puts("Wrong way to execute the program:\n"
           "\t\t./waitpid nProcesses\n"
         "example:\t./waitpid 2");

    return EXIT_FAILURE;
  }

  nproc = atol(argv[1]);  /* Process count */

  pids = CHECKALLOC(malloc(nproc * sizeof(pid_t)), "malloc");

  for (i = 0; i < nproc; i++) {

    int pid = fork();
	if(pid == 0) {
		childFunc(NULL);
		exit(0);
	} else {
		pids[i] = pid;
	}
  }

  sleep(1);

  for (i = 0; i < nproc; i++) {
    if (waitpid(pids[i], NULL, 0) == -1)
      ERREXIT("waitpid");
    printf("child %ld has terminated\n", (long)pids[i]);
  }

  free(pids);
  return EXIT_SUCCESS;
}
