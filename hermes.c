#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/prctl.h>

/* Needed for Seccomp-BPF syscall filtering */
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
#include <syscall.h>

#define BUFFER_SIZE 1024

void enable_seccomp() {

  struct sock_filter filter[] = {
    /* Load the system call number into the accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

    /* Syscall whitelist */
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 6, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 5, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 4, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 3, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk, 2, 0),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap, 1, 0),

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL), /* Kill process if any other syscall is performed */

    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), /* Allow returning success */
  };

  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };

  /* No new privileges allowed for this process */

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
    exit(EXIT_FAILURE);
  }

  /* Apply filter */
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("prctl(PR_SET_SECCOMP) failed");
    exit(EXIT_FAILURE);
  }
}


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

    enable_seccomp(); /* Restrict syscalls for untrusted code */

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

      case SIGSYS:
        printf("[Hermes] Security breach: System call blocked\n");
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
