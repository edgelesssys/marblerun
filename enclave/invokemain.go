package main

// #cgo LDFLAGS: -Wl,-unresolved-symbols=ignore-in-object-files
// void mountData(const char* path);
//
// #include <stdint.h>
//
// int oe_get_seal_key_by_policy_v2(
//     int seal_policy,
//     uint8_t** key_buffer,
//     size_t* key_buffer_size,
//     uint8_t** key_info,
//     size_t* key_info_size);
//
// void oe_free_seal_key(uint8_t* key_buffer, uint8_t* key_info);
import "C"

//export invokemain
func invokemain(cwd, config *C.char) {
	coordinatormain(C.GoString(cwd), C.GoString(config))
}

func main() {}
