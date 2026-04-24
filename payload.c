#include <stdio.h>
#include <stdlib.h>

int main() {
  printf("PAYLOAD: Executing untrusted code...\n");
  fprintf(stderr, "PAYLOAD: Simulated error message\n");
  printf("PAYLOAD: Completed.\n");
  return 42;
}
