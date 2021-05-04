cmake_minimum_required(VERSION 3.11)

project(marblerun VERSION 0.3.2)
execute_process(COMMAND bash "-c" "git rev-parse HEAD | tr -d '\n'" OUTPUT_VARIABLE GIT_COMMIT)
find_package(OpenEnclave CONFIG REQUIRED)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif ()
if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
  set(TRIMPATH -trimpath)
endif ()

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

#
# Build coordinator
#

add_custom_target(coordinatorlib
  ertgo build ${TRIMPATH} -buildmode=c-archive -tags enclave
  -o libcoordinator.a
  -ldflags "-X 'main.Version=${PROJECT_VERSION}' -X 'main.GitCommit=${GIT_COMMIT}'"
  ${CMAKE_SOURCE_DIR}/cmd/coordinator
)

add_custom_target(coordinator-noenclave ALL
  go build ${TRIMPATH}
  -o coordinator-noenclave
  -ldflags "-X 'main.Version=${PROJECT_VERSION}' -X 'main.GitCommit=${GIT_COMMIT}'"
  ${CMAKE_SOURCE_DIR}/cmd/coordinator)

add_executable(coordinator-enclave enclave/main.c)
add_dependencies(coordinator-enclave coordinatorlib)

target_link_libraries(coordinator-enclave
  openenclave::oeenclave
  openenclave::ertmeshentry
  ${CMAKE_BINARY_DIR}/libcoordinator.a
 )

# Sign enclave
add_custom_command(
  OUTPUT coordinator-enclave.signed
  DEPENDS coordinator-enclave enclave/coordinator.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:coordinator-enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/coordinator.conf -k private.pem)

# Create config for remote attestation
add_custom_command(
  OUTPUT coordinator-config.json
  DEPENDS coordinator-enclave.signed
  COMMAND openenclave::oesign eradump -e coordinator-enclave.signed > coordinator-config.json
)

add_custom_target(sign-coordinator ALL DEPENDS coordinator-enclave.signed coordinator-config.json)

#
# Build marble-injector
#

add_custom_target(marble-injector ALL
  CGO_ENABLED=0
  go build ${TRIMPATH}
  -o marble-injector
  ${CMAKE_SOURCE_DIR}/cmd/marble-injector
)

#
# Build CLI
#

set(cliPath "github.com/edgelesssys/marblerun/cli/cmd")
add_custom_target(cli ALL
  go build ${TRIMPATH}
  -o marblerun
  -ldflags "-X '${cliPath}.Version=${PROJECT_VERSION}' -X '${cliPath}.GitCommit=${GIT_COMMIT}'"
  ${CMAKE_SOURCE_DIR}/cli
)

#
# Build marble-test
#

add_custom_target(marbletestlib
  ertgo build ${TRIMPATH} -buildmode=c-archive
  -tags enclave -o libmarbletest.a
  ${CMAKE_SOURCE_DIR}/cmd/marble-test
)

add_custom_target(marble-test-noenclave ALL
  go build ${TRIMPATH}
  -o marble-test-noenclave
  ${CMAKE_SOURCE_DIR}/cmd/marble-test)

add_executable(marble-test-enclave enclave/main.c)
add_dependencies(marble-test-enclave marbletestlib)

target_link_libraries(marble-test-enclave
  openenclave::oeenclave
  openenclave::ertmeshentry
  ${CMAKE_BINARY_DIR}/libmarbletest.a
 )

# Sign enclave
add_custom_command(
  OUTPUT marble-test-enclave.signed
  DEPENDS marble-test-enclave enclave/marble-test.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:marble-test-enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/marble-test.conf -k private.pem)

# Create config for remote attestation
add_custom_command(
  OUTPUT marble-test-config.json
  DEPENDS marble-test-enclave.signed
  COMMAND openenclave::oesign eradump -e marble-test-enclave.signed > marble-test-config.json
)

add_custom_target(sign-marble-test ALL DEPENDS marble-test-enclave.signed marble-test-config.json)

#
# Build premain-graphene
#

add_custom_target(premain-graphene ALL ertgo build ${TRIMPATH} -buildmode=pie ${CMAKE_SOURCE_DIR}/cmd/premain-graphene)
