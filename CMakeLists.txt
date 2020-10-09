# Copyright (c) Edgeless Systems GmbH.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project(coordinator)
find_package(OpenEnclave CONFIG REQUIRED)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif ()

add_custom_target(coordinatorlib
  ertgo build -buildmode=c-archive
  -o libcoordinator.a
  ${CMAKE_SOURCE_DIR}/cmd/coordinator
)

add_custom_target(coordinator-noenclave ALL
  go build ${CMAKE_SOURCE_DIR}/cmd/coordinator-noenclave)

add_executable(enclave enclave/main.c)
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(enclave coordinatorlib)

target_link_libraries(enclave
  openenclave::ertmeshentry
  openenclave::oeenclave
  openenclave::oehostepoll
  openenclave::oehostfs
  openenclave::oehostsock
  ${CMAKE_BINARY_DIR}/libcoordinator.a
  crypto
  openenclave::ertlibc
  openenclave::oecustomfs
 )

# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT enclave.signed
  DEPENDS enclave enclave/enclave.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:enclave> -c
          ${CMAKE_SOURCE_DIR}/enclave/enclave.conf -k private.pem)

add_custom_target(sign ALL DEPENDS enclave.signed)

# Create config for remote attestation
add_custom_command(
  OUTPUT config.json
  DEPENDS enclave.signed
  COMMAND $(CMAKE_SOURCE_DIR)/tools/create_config.py -e $(CMAKE_BINARY_DIR)/enclave.signed -o $(CMAKE_BINARY_DIR)/config.json
)

add_custom_target(config ALL DEPENDS config.json)
