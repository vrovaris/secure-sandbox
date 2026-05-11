#include "hermes.h"

#define CGROUP_PATH "/sys/fs/cgroup/hermes_sandbox"

void write_to_file(const char *path, const char *value) {
    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("Cgroup write failed (Are you on Cgroups v2?)");
        return;
    }
    write(fd, value, strlen(value));
    close(fd);
}

void setup_cgroup(pid_t pid, size_t mem_limit_bytes) {
    mkdir(CGROUP_PATH, 0755);

    char mem_val[64];
    snprintf(mem_val, sizeof(mem_val), "%zu", mem_limit_bytes);
    char mem_limit_path[256];
    snprintf(mem_limit_path, sizeof(mem_limit_path), "%s/memory.max", CGROUP_PATH);
    write_to_file(mem_limit_path, mem_val);

    char pid_val[64];
    snprintf(pid_val, sizeof(pid_val), "%d", pid);
    char procs_path[256];
    snprintf(procs_path, sizeof(procs_path), "%s/cgroup.procs", CGROUP_PATH);
    write_to_file(procs_path, pid_val);
}

void cleanup_cgroup() {
    rmdir(CGROUP_PATH);
}
