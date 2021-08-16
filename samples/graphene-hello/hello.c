#include <stdio.h>
#include <string.h>

int main(int argc, char* argv[], char* envp[]) {
  puts("Hello world!\n\n\033[0;33mCommandline arguments:\033[0m");

  for (int i = 0; i < argc; ++i)
    puts(argv[i]);

  puts("\n\033[0;33mEnvironment variables:\033[0m");

  for (int i = 0; envp[i]; i++) {
    // Print envrionment variable value until we encounter a new line
    // This will reduce clutter from MarbleRun's certificates which we do not need to print necessarily
    char* chr = strchr(envp[i], '\n');

    if (chr != NULL) {
      int length_until_newline = chr - envp[i];
      printf("%.*s\n", length_until_newline, envp[i]);
    } else {
      printf("%s\n", envp[i]);
    }
  }

  return 0;
}
