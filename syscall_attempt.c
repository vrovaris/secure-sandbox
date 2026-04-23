#include <stdio.h>
#include <stdlib.h>

int main() {
  printf("SYSCALL_ATTEMPT: Trying to open file\n");

  FILE *fp = fopen("/etc/passwd", "r");
  if (fp == NULL) {
    printf("SYCALL_ATTEMPT: File not found or Syscall blocked\n");
    return 1;
  }
  printf("SYSCALL_ATTEMPT: File opened successfully\n");
  fclose(fp);
  return 0;
}
