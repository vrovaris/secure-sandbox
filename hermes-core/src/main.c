#include "hermes.h"

int main(int argc, char *argv[]) {
  if (argc < 2) {
    fprintf(stderr, "Usage: %s <program> [args...]\n", argv[0]);
    exit(EXIT_FAILURE);
  }

  // Pass the arguments (excluding the sandbox executable name) to our runner
  run_sandboxed(&argv[1]);

  return 0;
}
