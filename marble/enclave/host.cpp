#include <libgen.h>
#include <openenclave/host.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdlib>
#include <exception>
#include <fstream>
#include <iostream>
#include <iterator>
#include <string>
#include <system_error>

#include "emain_u.h"

using namespace std;

static string GetEnclavePath() {
  array<char, PATH_MAX> path{};
  const auto len = readlink("/proc/self/exe", path.data(), path.size() - 1);
  if (len == -1)
    throw system_error(errno, system_category(), "readlink");
  if (!(0 < len && len < PATH_MAX))
    throw runtime_error("readlink: unknown error");
  return dirname(path.data()) + "/enclave.signed"s;
}



int main(int argc, char *argv[]) {
  string enclavePath;
  try {
    enclavePath = GetEnclavePath();
  } catch (const exception &e) {
    cout << e.what() << '\n';
    return EXIT_FAILURE;
  }

  const char *const env_simulation = getenv("OE_SIMULATION");
  const bool simulate = env_simulation && *env_simulation == '1';

  const char *const coordinator_addr = getenv("EDG_COORDINATOR_ADDR");
  const char *const marble_type = getenv("EDG_MARBLE_TYPE");

  oe_enclave_t *enclave = nullptr;

  cout << "[marble] Loading enclave ...\n";
  if (oe_create_emain_enclave(
          enclavePath.c_str(),
          OE_ENCLAVE_TYPE_AUTO,
          OE_ENCLAVE_FLAG_DEBUG | (simulate ? OE_ENCLAVE_FLAG_SIMULATE : 0),
          nullptr,
          0,
          &enclave) != OE_OK ||
      !enclave) {
    cout << "oe_create_enclave failed\n";
    return EXIT_FAILURE;
  }

  cout << "[marble] Entering enclave ...\n";
  signal(SIGPIPE, SIG_IGN);
  int ret;
  if (emain(enclave, &ret, coordinator_addr, marble_type) != OE_OK)
    cout << "ecall failed\n";
  
  cout << "[marble] Terminating enclave...\n";
  // oe_terminate_enclave(enclave); // TODO: BUG 167

  return ret;
}
