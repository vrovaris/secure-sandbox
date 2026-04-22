#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/resource.h>


#define BUFFER_SIZE 1024

void run_sandboxed(char **argv) {
  int pipefd[2];
  pid_t pid;

  if (pipe(pipefd) != 0) {
    perror("pipe");
    exit(EXIT_FAILURE);
  }

  pid = fork();

  if (pid == 0) { /* Untrusted code */

    close(pipefd[0]);

    dup2(pipefd[1], 1);
    dup2(pipefd[1], 2);

    close(pipefd[1]);

    struct rlimit cpu_time_limit; /* Max running time */

    cpu_time_limit.rlim_cur = 2; /* Setting max 2 seconds */
    cpu_time_limit.rlim_max = 3;

    struct rlimit mem_limit; /* Max memory allowed */

    mem_limit.rlim_cur = 32 * 1024 * 1024; /* 32 MB */
    mem_limit.rlim_max = 32 * 1024 * 1024;

    if(setrlimit(RLIMIT_CPU, &cpu_time_limit) < 0 || setrlimit(RLIMIT_AS, &mem_limit) < 0) {
      perror("setrlimit");
      exit(EXIT_FAILURE);
    }

    execvp(argv[0], argv);
    perror("Hermes: execvp failed");
    exit(EXIT_FAILURE);
  }
  else { /* Sandbox */

    close(pipefd[1]);

    printf("[Hermes] Sandbox started for PID: %d\n", pid);
    printf("[Hermes] Capturing output:\n");
    printf("--------------------------------------------------\n");

    char buffer[BUFFER_SIZE];
    int bytes_read;

    while ((bytes_read = read(pipefd[0], buffer, sizeof(buffer) - 1)) > 0) {
      buffer[bytes_read] = '\0';
      printf("%s", buffer);
    }

    printf("--------------------------------------------------\n");

    int status;

    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
      printf("[Hermes] Process exited normally with status: %d\n", WEXITSTATUS(status));
    }
    else if (WIFSIGNALED(status)) {
      int signal_num = WTERMSIG(status);

      switch (signal_num) {
      case SIGXCPU:
        printf("[Hermes] Process killed: Time limit exceeded\n");
        break;

      case SIGSEGV:
        printf("[Hermes] Process killed: Segmentation fault\n");
        break;

      case SIGKILL:
        printf("[Hermes] Process killed: SIGKILL\n");
        break;

      default:
        printf("[Hermes] Process terminated by signal with following code: %d\n", signal_num);
        break;
      }
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // Pass the arguments (excluding the sandbox executable name) to our runner
  run_sandboxed(&argv[1]);

  return 0;
}
