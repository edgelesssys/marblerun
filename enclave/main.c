#include <stdio.h>

int main() {
  // verify that the symcrypt module has been loaded for FIPS support
  int oe_is_symcrypt_provider_available(void);
  if (oe_is_symcrypt_provider_available() != 1) {
    puts("symcrypt provider is not available");
    return 1;
  }

  void invokemain(void);
  invokemain();
  return 0;
}
