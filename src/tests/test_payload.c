#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

void test_output() {
  printf("NORMAL: Hello from the sandbox!\n");
  exit(42);
}

void test_timeout() {
  printf("TEST_TIMEOUT: Starting infinite loop...\n");
  while(1);
}

void test_virtual_memory() {
  printf("VIRTUAL_MEMORY: Attempting to allocate 100MB of VM...\n");
  size_t size = 100 * 1024 * 1024;
  void *ptr = malloc(size);
  if (ptr == NULL) {
    printf("RESULT: Malloc failed (Limit enforced)\n");
    exit(0);
  }
  memset(ptr, 1, size);
  printf("RESULT: Malloc succeeded (Limit failed)\n");
}

void test_physical_memory() {
    printf("PHYSICAL_MEMORY: Attempting to allocate and touch 100MB of physical RAM...\n");
    size_t size = 100 * 1024 * 1024; // 100 MB
    volatile char *ptr = malloc(size);
    if (ptr == NULL) {
        printf("RESULT: Malloc failed (Limit enforced)\n");
        exit(0);
    }

    // Touch every page (4KB) to force the OS to assign physical RAM (RSS).
    for (size_t i = 0; i < size; i += 4096) {
        ptr[i] = 'A';
    }

    printf("RESULT: Malloc succeeded (Limit failed)\n");
}

void test_syscall() {
  printf("TEST_SYSCALL: Attempting to open a network socket...\n");
  int s = socket(AF_INET, SOCK_STREAM, 0);
  if (s >= 0) printf("RESULT: Socket opened (Seccomp failed)\n");
}

void test_jail() {
  printf("TEST_JAIL: Attempting to read /etc/passwd...\n");
  FILE *f = fopen("/etc/passwd", "r");
  if (f == NULL) {
    printf("RESULT: File inaccessible (Jail works)\n");
    exit(0);
  }
  printf("RESULT: Read /etc/passwd (Jail failed)\n");
  fclose(f);
}

void test_namespace() {

  printf("NAMESPACE: PID = %d\n", getpid());
}

int main(int argc, char *argv[]) {
  if (argc < 2) return 1;

  if (strcmp(argv[1], "output") == 0)  test_output();
  if (strcmp(argv[1], "timeout") == 0) test_timeout();
  if (strcmp(argv[1], "virtual_memory") == 0)  test_virtual_memory();
  if (strcmp(argv[1], "physical_memory") == 0) test_physical_memory();
  if (strcmp(argv[1], "syscall") == 0) test_syscall();
  if (strcmp(argv[1], "jail") == 0)    test_jail();
  if (strcmp(argv[1], "namespace") == 0) test_namespace();

  return 0;
}
