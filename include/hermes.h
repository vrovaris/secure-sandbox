#ifndef HERMES_H
#define HERMES_H

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sched.h>

/* Needed for Seccomp-BPF syscall filtering */
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <stddef.h>
#include <syscall.h>
#include <sys/utsname.h>
#include <sys/mount.h>

#define STACK_SIZE (1024 * 1024)
#define BUFFER_SIZE 1024

typedef struct {
    char **argv;
    int pipe_write_end;
    char *base_dir;
} child_args_t;

void enable_seccomp();
int child_main(void *arg);
void run_sandboxed(char **argv);
void setup_cgroup(pid_t pid, size_t mem_limit_bytes);
void cleanup_cgroup();

#endif
