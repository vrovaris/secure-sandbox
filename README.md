# Hermes: High-Performance Linux Sandbox

Hermes is a secure, defense-in-depth code execution engine written entirely in C. It is designed to safely execute untrusted, statically-linked binaries by heavily restricting their access to system resources, the filesystem, and the OS kernel.

This project was built to explore low-level Systems Engineering, mirroring the core architecture of container runtimes (like Docker/runc) and code-judging backend engines (like those powering LeetCode or Codeforces).

---

## Core Security Architecture

Hermes relies on a multi-layered security model using native Linux primitives:

### Linux Namespaces (`clone`)
Creates a completely isolated view of the system for each execution:
- `CLONE_NEWPID` — The sandboxed process believes it is PID 1; it cannot see host processes.
- `CLONE_NEWNET` — A completely empty network stack with no internet access.
- `CLONE_NEWNS` — A private mount namespace to prevent filesystem leaks.

### Filesystem Jail (`chroot`)
Each execution runs inside a thread-safe, UUID-based temporary directory created with `mkdtemp`. The sandbox copies the binary into this empty jail and calls `chroot` to make it the new root. The process cannot access any host file (e.g., `/etc/passwd`, `/usr/bin`). Before execution begins, the sandbox drops root privileges with `setuid(1000)`.

### Resource Limits
Two complementary mechanisms enforce resource limits:

- **POSIX `rlimit`** — Sets hard limits on CPU time (2s soft / 3s hard) and virtual address space (32 MB). Violations send `SIGXCPU` or terminate the process.
- **Control Groups v2 (`cgroups`)** — Enforces a strict physical memory (RSS) cap by writing to `/sys/fs/cgroup/hermes_sandbox/memory.max`. Unlike `RLIMIT_AS` (which limits virtual memory and can break modern runtimes like Go), cgroups enforce true RAM usage and trigger the kernel OOM-killer if the limit is breached.

### Seccomp-BPF (System Call Filtering)
A strict kernel-level system call whitelist is installed using `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ...)`. If the untrusted code attempts any unauthorized syscall (e.g., `socket`, `fork`, `clone`), the kernel immediately terminates it with `SIGSYS`. The whitelist is tuned for both x86_64 and ARM64 and covers only the syscalls required to run a statically-linked binary.

### IPC Telemetry
`stdout` and `stderr` of the sandboxed process are captured via an unidirectional pipe (`pipe` + `dup2`). The parent process streams output to the terminal and then collects the child's exit status via `waitpid`, decoding the termination reason (normal exit, time limit, segfault, OOM-kill, or seccomp violation).

---

## Project Structure

```
.
├── Makefile
├── test_suite.sh            # Integration test suite
├── include/
│   └── hermes.h             # Core definitions and shared prototypes
└── src/
    ├── main.c               # Entry point (argument parsing)
    ├── sandbox.c            # Process management, namespaces, chroot jail, IPC
    ├── seccomp.c            # BPF system call whitelist
    ├── cgroup.c             # Cgroups v2 physical memory limiting
    └── tests/
        └── test_payload.c   # Unified malware simulation payload
```

---

## Building & Testing

**Prerequisites:** Linux (x86_64 or ARM64), `gcc`, `make`.

> **Note:** Execution requires `sudo` to initialize namespaces, cgroups, and the chroot jail.

```bash
# 1. Compile the sandbox and the test payload
make

# 2. Run the automated integration test suite
chmod +x test_suite.sh
sudo ./test_suite.sh
```

### Test Cases

The test suite (`test_suite.sh`) exercises every security layer by running a single unified payload binary (`test_payload`) with different arguments:

| Test | Payload argument | Verifies |
|---|---|---|
| Normal Output | `output` | Sandbox captures stdout and reports exit code 42 |
| Time Limit | `timeout` | Infinite loop is killed; `SIGXCPU` or `SIGKILL` reported |
| Virtual Memory Limit | `virtual_memory` | `malloc(100 MB)` fails due to `RLIMIT_AS` |
| Physical Memory Limit | `physical_memory` | Touching 100 MB of RAM triggers cgroup OOM-killer |
| Seccomp Filter | `syscall` | `socket()` call is blocked; process killed with `SIGSYS` |
| Filesystem Jail | `jail` | `/etc/passwd` is inaccessible inside the chroot |
| PID Namespace | `namespace` | Sandboxed process reports PID 1 |

---

## Design Trade-Offs

### The Static Linking Requirement
Because Hermes uses an empty `chroot` jail for maximum filesystem isolation, dynamically linked binaries will fail to execute — they cannot reach the host's `/lib` directory to load the C standard library. Instead of bundling a full root filesystem (like Docker does), Hermes adopts the "code execution" threat model: submitted binaries must be compiled with the `-static` flag. This produces a self-contained binary that can run inside an empty jail under a hyper-strict seccomp whitelist.

### `rlimit` vs. Cgroups for Memory
`RLIMIT_AS` limits the *virtual* address space, which causes false positives with modern allocators and runtimes that reserve large virtual regions upfront. Cgroups v2 `memory.max` limits *physical* RSS instead, providing accurate enforcement without breaking legitimate allocator patterns. Hermes applies both: `RLIMIT_AS` as a fast first line of defense and cgroups as the definitive physical RAM cap.
