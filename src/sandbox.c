#include "hermes.h"

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

