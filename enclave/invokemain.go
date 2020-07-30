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
	edbmain(C.GoString(cwd), C.GoString(config))
}

/*
func mountData(path string) {
	C.mountData((*C.char)(unsafe.Pointer(&[]byte(path)[0])))
}

func getProductSealKey() ([]byte, error) {
	// TODO move to ertgolib
	var key *C.uint8_t
	var keySize C.size_t
	if C.oe_get_seal_key_by_policy_v2(2, &key, &keySize, nil, nil) != 0 {
		return nil, errors.New("failed to get seal key")
	}

	result := C.GoBytes(unsafe.Pointer(key), C.int(keySize))
	C.oe_free_seal_key(key, nil)
	return result, nil
}
*/
