#include "hermes.h"

#ifndef SYS_rseq
#define SYS_rseq 293
#endif

#define ALLOW_SYSCALL(name) \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, name, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

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
