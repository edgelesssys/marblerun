#include <openenclave/enclave.h>
#include <openenclave/enclave_args.h>
#include <sys/mount.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "emain_t.h"

extern "C" int invokemain(char *, char *);

int emain(char *coordinator_addr, char *marble_type) {
  if (oe_load_module_host_epoll() != OE_OK ||
      oe_load_module_host_file_system() != OE_OK ||
      oe_load_module_host_socket_interface() != OE_OK) {
    puts("oe_load_module_host failed");
    return -3;
  }
  
  return invokemain(coordinator_addr, marble_type);
}
