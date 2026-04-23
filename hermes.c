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

#define ALLOW_SYSCALL(name) \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, name, 0, 1), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

void enable_seccomp() {

  struct sock_filter filter[] = {
    /* Load the system call number into the accumulator */
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

    /* Syscall whitelist */
    ALLOW_SYSCALL(SYS_execve),  // Required to start the program
    ALLOW_SYSCALL(SYS_read),    // Required for IO
    ALLOW_SYSCALL(SYS_write),   // Required for printf
    ALLOW_SYSCALL(SYS_exit),    // Required to close normally
    ALLOW_SYSCALL(SYS_exit_group),
    ALLOW_SYSCALL(SYS_brk),     // Required for malloc
    ALLOW_SYSCALL(SYS_mmap),    // Required for malloc
    ALLOW_SYSCALL(SYS_prctl), // glibc static setup
    ALLOW_SYSCALL(SYS_uname),      // glibc static setup
    ALLOW_SYSCALL(SYS_set_tid_address), // glibc static setup
    ALLOW_SYSCALL(SYS_set_robust_list), // glibc static setup
    ALLOW_SYSCALL(SYS_ioctl),      // printf checking if stdout is a terminal
    ALLOW_SYSCALL(SYS_fstat),      // printf checking stdout status
    ALLOW_SYSCALL(SYS_readlinkat),   // glibc static setup
    ALLOW_SYSCALL(SYS_rseq),
    ALLOW_SYSCALL(SYS_getrandom),   // 318: To initialize the stack canary (buffer overflow protection)
    ALLOW_SYSCALL(SYS_mprotect),    // 10:  Setting memory permissions (read/write/exec)
    ALLOW_SYSCALL(SYS_prlimit64),   // 302: glibc checking its own limits
    ALLOW_SYSCALL(SYS_fstat),       // 5:   Checking file info (for stdout/stderr)
    ALLOW_SYSCALL(SYS_newfstatat),  // 262: Newer version of fstat used on some kernels
    ALLOW_SYSCALL(SYS_set_tid_address), // 218: Threading setup
    ALLOW_SYSCALL(SYS_set_robust_list), // 273: Mutex/locking setup


    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL), /* Kill process if any other syscall is performed */
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
