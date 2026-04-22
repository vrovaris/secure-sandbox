#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {

  printf("MALWARE: Memory consumer\n");
  int mb = 0;

  while (1) {

    void *ptr = malloc(1024*1024);
    if (ptr == NULL) {
      printf("MALWARE: Malloc failed at %d MB.\n", mb);
      break;
    }
    memset(ptr, 'A', 1024*1024);
    mb++;
  }
  return 0;
}
