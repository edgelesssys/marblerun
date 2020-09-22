#include <openenclave/enclave.h>
#include <openenclave/enclave_args.h>
#include <openenclave/ert.h>
#include <sys/mount.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "emain_t.h"

using namespace std;

extern "C" void invokemain(const char* cwd, const char* config);

void emain(const char* cwd, const char* config) {
  if (oe_load_module_host_epoll() != OE_OK ||
      oe_load_module_host_file_system() != OE_OK ||
      oe_load_module_host_socket_interface() != OE_OK) {
    puts("oe_load_module_host failed");
    return;
  }
  const char* const devname_tmpfs = "tmpfs";
  const ert::Memfs memfs(devname_tmpfs);

  if (mount("/", "/tmp/", devname_tmpfs, 0, nullptr) != 0) {
    puts("mount tmpfs failed");
    return;
  }
  invokemain(cwd, config);
}

extern "C" void mountData(const char* path) {
  bool success = false;
  if (mkdir_ocall(&success, path) != OE_OK || !success) {
    puts("mkdir dataPath failed");
    abort();
  }

  if (mount(path, "/coordinator/data", OE_HOST_FILE_SYSTEM, 0, nullptr) != 0) {
    puts("mount data failed");
    abort();
  }
}
