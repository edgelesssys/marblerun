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

static string ReadConfig(const string &config_filename) {
  if (config_filename.empty())
    return string();
  ifstream f;
  f.exceptions(ios::badbit | ios::failbit | ios::eofbit);
  f.open(config_filename);
  return string(istreambuf_iterator<char>(f), istreambuf_iterator<char>());
}

static string GetCwd() {
  array<char, PATH_MAX> cwd{};
  if (getcwd(cwd.data(), cwd.size()) != cwd.data())
    throw system_error(errno, system_category(), "getcwd");
  return cwd.data();
}

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
  // parse args
  string config_filename;
  int opt;
  while ((opt = getopt(argc, argv, "c:")) != -1) {
    switch (opt) {
      case 'c':
        config_filename = optarg;
        break;
      default:
        cout << "Usage: " << argv[0] << " [-c config]\n";
        return EXIT_FAILURE;
    }
  }

  string config;
  string cwd;
  string enclavePath;
  try {
    config = ReadConfig(config_filename);
    cwd = GetCwd();
    enclavePath = GetEnclavePath();
  } catch (const exception &e) {
    cout << e.what() << '\n';
    return EXIT_FAILURE;
  }

  const char *const env_simulation = getenv("OE_SIMULATION");
  const bool simulate = env_simulation && *env_simulation == '1';

  oe_enclave_t *enclave = nullptr;

  cout << "[coordinator] Loading enclave ...\n";
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

  cout << "[coordinator] Entering enclave ...\n";
  signal(SIGPIPE, SIG_IGN);
  if (emain(enclave, cwd.c_str(), config.c_str()) != OE_OK)
    cout << "ecall failed\n";

  oe_terminate_enclave(enclave);
}