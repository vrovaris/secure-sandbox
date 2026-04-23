#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>

/* Needed for Seccomp-BPF syscall filtering */
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
#include <syscall.h>
#include <sys/utsname.h> 

#ifndef SYS_rseq
#define SYS_rseq 293
#endif

#define BUFFER_SIZE 1024

#define ALLOW_SYSCALL(name) \
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, name, 0, 1), \
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

void enable_seccomp();

void run_sandboxed(char **argv) {
  int pipefd[2];
  pid_t pid;

  if (pipe(pipefd) != 0) {
    perror("pipe");
    exit(EXIT_FAILURE);
  }

  /* Create the jail directory and copy the executable there */
  mkdir("/tmp/chroot_jail", 0755);

  char copy_cmd[BUFFER_SIZE];
  snprintf(copy_cmd, sizeof(copy_cmd), "cp %s /tmp/chroot_jail/app_bin", argv[0]);
  system(copy_cmd);

  argv[0] = "/app_bin"; /* Update where the file will be executed */

  pid = fork();

  if (pid == 0) { /* Untrusted code */

    close(pipefd[0]);

    /* Move to the jail */
    if (chdir("/tmp/chroot_jail") != 0) {
      perror("chdir");
      exit(EXIT_FAILURE);
    }

    /* Change root directory for the child process */
    if (chroot("/tmp/chroot_jail") != 0) {
      perror("chroot");
      exit(EXIT_FAILURE);
    }

    if (setuid(1000) != 0) { /* Ensure we're back to user mode and not root */
      perror("setuid");
      exit(EXIT_FAILURE);
    }

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

    //printf("--------------------------------------------------\n");

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

void enable_seccomp() {
  struct sock_filter filter[] = {
    // 1. Load the system call number
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, (offsetof(struct seccomp_data, nr))),

    // --- THE ARM64 MASTER WHITELIST ---
    ALLOW_SYSCALL(SYS_execve),      // Start the program
    ALLOW_SYSCALL(SYS_brk),         // Memory allocation (malloc)
    ALLOW_SYSCALL(SYS_mmap),        // Memory mapping
    ALLOW_SYSCALL(SYS_mprotect),    // Memory permissions
    ALLOW_SYSCALL(SYS_munmap),      // Memory cleanup
    ALLOW_SYSCALL(SYS_read),        // I/O
    ALLOW_SYSCALL(SYS_write),       // I/O
    ALLOW_SYSCALL(SYS_close),       // I/O
    ALLOW_SYSCALL(SYS_openat),      // I/O
    ALLOW_SYSCALL(SYS_fstat),       // File stats
    ALLOW_SYSCALL(SYS_newfstatat),  // Modern file stats
    ALLOW_SYSCALL(SYS_readlinkat),  // Dynamic linker path resolution

    // --- PROCESS & SIGNAL SETUP ---
    ALLOW_SYSCALL(SYS_rt_sigprocmask),
    ALLOW_SYSCALL(SYS_rt_sigaction),
    ALLOW_SYSCALL(SYS_rt_sigreturn), // Critical for returning from signals
    ALLOW_SYSCALL(SYS_set_tid_address),
    ALLOW_SYSCALL(SYS_set_robust_list),
    ALLOW_SYSCALL(SYS_futex),        // Threading primitives
    ALLOW_SYSCALL(SYS_rseq),         // Syscall 293 (Restartable sequences)
    ALLOW_SYSCALL(SYS_prlimit64),    // Resource limit checks
    ALLOW_SYSCALL(SYS_getrandom),    // Stack canary initialization
    ALLOW_SYSCALL(SYS_uname),        // 160: Kernel version check
    ALLOW_SYSCALL(SYS_prctl),        // 167: Process feature checks
    ALLOW_SYSCALL(SYS_getpid),
    ALLOW_SYSCALL(SYS_getuid),
    ALLOW_SYSCALL(SYS_getgid),
    ALLOW_SYSCALL(SYS_geteuid),
    ALLOW_SYSCALL(SYS_getegid),
    ALLOW_SYSCALL(SYS_exit),         // Allow the program to exit
    ALLOW_SYSCALL(SYS_exit_group),   // Allow multi-threaded programs to exit

    // --- FILE ACCESS FAMILY ---
    ALLOW_SYSCALL(SYS_faccessat),    // 48
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 439, 0, 1), BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW), // faccessat2

    // --- CATCH-ALL KILL ---
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL)
  };

  struct sock_fprog prog = {.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter};

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
    perror("prctl(PR_SET_NO_NEW_PRIVS) failed");
    exit(EXIT_FAILURE);
  }
  if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == -1) {
    perror("prctl(PR_SET_SECCOMP) failed");
    exit(EXIT_FAILURE);
  }
}
