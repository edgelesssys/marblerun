#include <stdio.h>

int main(int argc, char* argv[]) {
  puts("Hello world!\nCommandline arguments:");

  for (int i = 0; i < argc; ++i)
    puts(argv[i]);

  return 0;
}
