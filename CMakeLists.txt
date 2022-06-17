cmake_minimum_required(VERSION 3.11)

project(marblerun VERSION 0.6.0)
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

add_custom_target(
  signing-key
  DEPENDS private.pem)

#
# Build coordinator
#

add_custom_target(coordinatorlib
  COMMAND
  ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/build_with_version.cmake
  "ertgo" ${PROJECT_VERSION} "libcoordinator.a"
  "${CMAKE_SOURCE_DIR}/cmd/coordinator" "main"
  ${TRIMPATH}
)

add_custom_target(coordinator-noenclave ALL
  COMMAND
  ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/build_with_version.cmake
  "go" ${PROJECT_VERSION} "coordinator-noenclave"
  "${CMAKE_SOURCE_DIR}/cmd/coordinator" "main"
   ${TRIMPATH}

)

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
  DEPENDS coordinator-enclave enclave/coordinator.conf signing-key
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

add_custom_target(cli ALL
  COMMAND
  ${CMAKE_COMMAND} -P ${CMAKE_SOURCE_DIR}/build_with_version.cmake
  "go" "${PROJECT_VERSION}" "marblerun"
  "${CMAKE_SOURCE_DIR}/cli" "github.com/edgelesssys/marblerun/cli/cmd"
  ${TRIMPATH}
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
  DEPENDS marble-test-enclave enclave/marble-test.conf signing-key
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
# Build premain-libos
#

add_custom_target(premain-libos ALL ertgo build ${TRIMPATH} -buildmode=pie ${CMAKE_SOURCE_DIR}/cmd/premain-libos)
