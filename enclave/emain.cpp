#include <openenclave/enclave.h>
#include <openenclave/enclave_args.h>
#include <sys/mount.h>

#include <array>
#include <cstdio>
#include <cstdlib>
#include <iostream>

#include "emain_t.h"

//using namespace edgeless;

extern "C" void invokemain(const char* cwd, const char* config);

void emain(const char* cwd, const char* config) {
  if (oe_load_module_host_epoll() != OE_OK ||
      oe_load_module_host_file_system() != OE_OK ||
      oe_load_module_host_socket_interface() != OE_OK) {
    puts("oe_load_module_host failed");
    return;
  }

  /*
  const char* const devname_tmpfs = "tmpfs";
  oe_customfs_t tmpfs{};
  tmpfs.open = tmpfs::open;
  tmpfs.close = tmpfs::close;
  tmpfs.get_size = tmpfs::get_size;
  tmpfs.unlink = tmpfs::unlink;
  tmpfs.read = tmpfs::read;
  tmpfs.write = tmpfs::write;

  if (oe_load_module_custom_file_system(devname_tmpfs, &tmpfs) != OE_OK) {
    puts("load tmpfs failed");
    return;
  }

  if (mount("/", "/edb/tmp", devname_tmpfs, 0, nullptr) != 0) {
    puts("mount tmpfs failed");
    return;
  }
  */
  std::cout << "emain" << std::endl;
  invokemain(cwd, config);
}

/*
oe_args_t oe_get_args() {
  static const std::array<const char*, 3> argv{
      "/edb/edb",
      "-config",
      "/edb/tmp/tidbcfg",
  };

  static const std::array<const char*, 1> envp{
      "GOMAXPROCS=2",  // This also prevents an error that would be logged: the automaxprocs package would try to open /proc/self/cgroup
  };

  oe_args_t args{};
  args.argv = argv.data();
  args.argc = argv.size();
  args.envp = envp.data();
  args.envc = envp.size();
  return args;
}

extern "C" void mountData(const char* path) {
  bool success = false;
  if (mkdir_ocall(&success, path) != OE_OK || !success) {
    puts("mkdir dataPath failed");
    abort();
  }

  if (mount(path, "/edb/data", OE_HOST_FILE_SYSTEM, 0, nullptr) != 0) {
    puts("mount data failed");
    abort();
  }
}
*/