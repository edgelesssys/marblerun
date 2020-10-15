cmake_minimum_required(VERSION 3.11)

add_custom_command(
  OUTPUT libertmeshpremain.a
  DEPENDS main.go
  COMMAND ertgo build -buildmode=c-archive -o libertmeshpremain.a ${CMAKE_SOURCE_DIR}/main.go)

add_custom_target(ertmeshpremain ALL DEPENDS libertmeshpremain.a)
install(FILES ${CMAKE_BINARY_DIR}/libertmeshpremain.a DESTINATION lib)
