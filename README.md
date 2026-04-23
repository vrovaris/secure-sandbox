# Secure Execution Sandbox

Hermes is a lightweight, defense-in-depth Linux sandbox written entirely in C. It is designed to safely execute untrusted statically-linked binaries by
heavily restricting their access to system resources, the filesystem, and the OS Kernel.

This project include Inter-Process Communication (IPC), POSIX system calls, process management, and kernel-level security primitives.

## Features
* **Filesystem Isolation:** Traps untrusted code inside an empty `chroot` jail, preventing access to host files, such as /usr/bin
* **Kernel Attack Surface Reduction:** Uses **Seccomp-BPF** (Secure Computing + Berkeley Packet Filters) to enforce a strict system call *whitelist*, instantly
killing the process (`SIGSYS`) if it attempts unauthorized actions like opening network sockets or forking background processes.
* **Hardware Resource Limits:** Prevents Denial of Service (DoS) attacks by enforcing soft and hard limits on CPU time and Virtual Memory.
* **Privilege Dropping:** Safely drops from `root` to standard user privileges (`setuid`) before execution to prevent jail-breaking.
* **IPC Telemetry:** Captures `stdout` and `stderr` of the untrusted process via pipes, reporting exit statuses and terminal signals.

## Architecture & Trade-Offs
**Static vs. Dynamic Linking**
This project enforces the use of statically linked binaries. Because Hermes uses an empty `chroot` jail for filesystem security, dynamically linked binaries
fail to execute (as they cannot access the host's `/lib` directory to load the C Standard Library).
Instead of providing a heavy root filesystem (like Docker), Hermes adopts the "Code Execution" threat mode, that is, the backend compiles user-submitted source
code with the `-static` flag, resulting in a self-contained binary that can be safely executed in an empty jail with an ultra-strict Seccomp whitelist.

## Building & Testing
**Prerequisites:** Linux environment (x86_64 or ARM64), `gcc`, `make`. *Note: Execution requires `sudo` to initialize the `chroot` jail.*

```bash
# 1. Compile the sandbox and the test payload and executable
make

# 2. Run the automated integration test suite
chmod +x test_all.sh
sudo ./test_all.sh# sandbox-project
