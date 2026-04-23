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

void test_memory() {
  printf("TEST_MEMORY: Attempting to allocate 100MB...\n");
  size_t size = 100 * 1024 * 1024;
  void *ptr = malloc(size);
  if (ptr == NULL) {
    printf("RESULT: Malloc failed (Limit enforced)\n");
    exit(0);
  }
  memset(ptr, 1, size);
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

int main(int argc, char *argv[]) {
  if (argc < 2) return 1;

  if (strcmp(argv[1], "output") == 0)  test_output();
  if (strcmp(argv[1], "timeout") == 0) test_timeout();
  if (strcmp(argv[1], "memory") == 0)  test_memory();
  if (strcmp(argv[1], "syscall") == 0) test_syscall();
  if (strcmp(argv[1], "jail") == 0)    test_jail();

  return 0;
}
