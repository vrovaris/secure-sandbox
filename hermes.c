#define _GNU_SOURCE

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
#include <sys/mount.h>

/* Stack allocation and clone() */
#include <sched.h>
#include <sys/mman.h>

#ifndef SYS_rseq
#define SYS_rseq 293
#endif

#define BUFFER_SIZE 1024
#define STACK_SIZE (1024*1024)

#define ALLOW_SYSCALL(name) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, name, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

typedef struct {
  char **argv;
  int pipe_write_end;
  char *base_dir;
} child_args_t;

void enable_seccomp();
int child_main(void *arg);
void run_sandboxed(char **argv);

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


void run_sandboxed(char **argv) {
  int pipefd[2];
  pid_t pid;

  if (pipe(pipefd) != 0) {
    perror("pipe");
    exit(EXIT_FAILURE);
  }

  /* Create the jail directory and copy the executable there. Also create a new /proc to avoid any leaks to the host machine's info. */
  char base_dir[] = "/tmp/chroot_jail_XXXXXX";

  if (mkdtemp(base_dir) == NULL) {
    perror("mkdtemp");
    exit(EXIT_FAILURE);
  }

  chmod(base_dir, 0755);

  char proc_dir[sizeof(base_dir) + sizeof("/proc")];
  snprintf(proc_dir, sizeof(proc_dir), "%s/proc", base_dir);

  if (mkdir(proc_dir, 0755) != 0) {
    perror("mkdir");
    exit(EXIT_FAILURE);
  }

  char app_bin[sizeof(base_dir) + sizeof("/app_bin")];
  snprintf(app_bin, sizeof(app_bin), "%s/app_bin", base_dir);

  // TODO - Revisit system() safety
  char cmd[BUFFER_SIZE  + sizeof(app_bin)];
  snprintf(cmd, sizeof(cmd), "cp %s %s", argv[0], app_bin);

  system(cmd);

  argv[0] = "/app_bin"; /* Update where the file will be executed */

  /* Build specific argument for creating the child process */
  child_args_t *args = malloc(sizeof(child_args_t));

  if (args == NULL) {
    perror("malloc");
    exit(EXIT_FAILURE);
  }

  args->argv = argv;
  args->pipe_write_end = pipefd[1];
  args->base_dir = strdup(base_dir);

  /* Allocate a separate stack because of clone() */
  char *stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);

  if (stack == MAP_FAILED) {
    perror("mmap");
    exit(EXIT_FAILURE);
  }

  int flags = CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWNS | SIGCHLD;

  // Note: stack + STACK_SIZE because the stack grows downwards on x86/ARM
  pid = clone(child_main, stack + STACK_SIZE, flags, args);

  if (pid == -1) {
    perror("clone");
    exit(EXIT_FAILURE);
  }

  /* Sandbox */

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

  /* CLEANUP */

  /* Recollect the memory used */
  free(args->base_dir);
  free(args);
  args = NULL;
  munmap(stack, STACK_SIZE);

  /* Unmount proc */

  umount2(proc_dir, MNT_DETACH);

  // TODO - Review system() safety
  snprintf(cmd, sizeof(cmd), "rm -rf %s", base_dir);
  system(cmd);

  /* Exit status of child process */
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


int child_main(void *arg) {

  child_args_t *args = (child_args_t *) arg;

  if (args == NULL) {
    perror("args");
    exit(EXIT_FAILURE);
  }

  char **argv = args->argv;
  int pipe_write_end = args->pipe_write_end;
  char *base_dir = args->base_dir;

  /* Move to the jail */
  if (chdir(base_dir) != 0) {
    perror("chdir");
    exit(EXIT_FAILURE);
  }

  /* Change root directory for the child process */
  if (chroot(base_dir) != 0) {
    perror("chroot");
    exit(EXIT_FAILURE);
  }

  if (chdir("/") != 0) {
    perror("chdir");
    exit(EXIT_FAILURE);
  }

  /* Remount proc */
  if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
    perror("mount");
    exit(EXIT_FAILURE);
  }

  /* Ensure we're back to user mode and not root */
  if (setuid(1000) != 0) {
    perror("setuid");
    exit(EXIT_FAILURE);
  }

  dup2(pipe_write_end, 1);
  dup2(pipe_write_end, 2);

  close(pipe_write_end);

  struct rlimit cpu_time_limit; /* Max running time */

  cpu_time_limit.rlim_cur = 2; /* Setting max 2 seconds */
  cpu_time_limit.rlim_max = 3;

  struct rlimit mem_limit; /* Max memory allowed */

  mem_limit.rlim_cur = 32 * 1024 * 1024; /* 32 MB */
  mem_limit.rlim_max = 32 * 1024 * 1024;

  if (setrlimit(RLIMIT_CPU, &cpu_time_limit) < 0 || setrlimit(RLIMIT_AS, &mem_limit) < 0) {
    perror("setrlimit");
    exit(EXIT_FAILURE);
  }

  enable_seccomp(); /* Restrict syscalls for untrusted code */

  execvp(argv[0], argv);
  perror("Hermes: execvp failed");
  exit(EXIT_FAILURE);
}
