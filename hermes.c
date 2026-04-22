#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>

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
      printf("[Hermes] Process terminated by signal with following code: %d\n", WTERMSIG(status));
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
