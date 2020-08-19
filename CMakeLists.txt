# Copyright (c) Edgeless Systems GmbH.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)
find_package(OpenEnclave CONFIG REQUIRED)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_EXTENSIONS OFF)

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Debug)
endif ()

add_custom_target(app ertgo build -buildmode=c-archive
  -o coordinator.a
  ${CMAKE_SOURCE_DIR}/enclave/invokemain.go
  ${CMAKE_SOURCE_DIR}/enclave/coordinatormain.go
)

# Use the edger8r to generate C bindings from the EDL file.
add_custom_command(
  OUTPUT emain_t.c emain_u.c
  DEPENDS enclave/emain.edl
  COMMAND openenclave::oeedger8r ${CMAKE_SOURCE_DIR}/enclave/emain.edl --search-path
          ${OE_INCLUDEDIR} --search-path ${OE_INCLUDEDIR}/openenclave/edl/sgx)

add_executable(enclave enclave/emain.cpp emain_t.c) #enclave/stubs.c
target_include_directories(enclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
add_dependencies(enclave app)

target_link_libraries(enclave -static
  openenclave::oeenclave
  openenclave::oehostepoll
  openenclave::oehostfs
  openenclave::oehostsock
  openenclave::oecustomfs
  crypto
  openenclave::oecore
  openenclave::oelibcxx
  ${CMAKE_BINARY_DIR}/coordinator.a
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

# Build the host
add_executable(coordinator enclave/host.cpp emain_u.c)
target_include_directories(coordinator PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(coordinator openenclave::oehost)
