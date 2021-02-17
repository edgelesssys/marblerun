package main

// #include <spawn.h>
// #include <sys/wait.h>
import "C"

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"os"
	"strings"
	"syscall"

	"github.com/edgelesssys/marblerun/marble/premain"
	"github.com/spf13/afero"
)

func main() {
	// filter env vars
	for _, env := range os.Environ() {
		if !strings.HasPrefix(env, "EDG_") && !strings.HasPrefix(env, "LD_LIBRARY_PATH=") {
			if err := os.Unsetenv(strings.SplitN(env, "=", 2)[0]); err != nil {
				panic(err)
			}
		}
	}

	// save the passed argument which is our service to spawn
	service := os.Args[0]

	hostfs := afero.NewOsFs()
	if err := premain.PreMainEx(quoteIssuer{}, hostfs, hostfs); err != nil {
		panic(err)
	}

	argv := toCArray(os.Args)
	envp := toCArray(os.Environ())

	// spawn service
	if res := C.posix_spawn(nil, C.CString(service), nil, nil, &argv[0], &envp[0]); res != 0 {
		panic(syscall.Errno(res))
	}
	C.wait(nil)
}

func toCArray(arr []string) []*C.char {
	result := make([]*C.char, len(arr)+1)
	for i, s := range arr {
		result[i] = C.CString(s)
	}
	return result
}

type quoteIssuer struct{}

func (quoteIssuer) Issue(cert []byte) ([]byte, error) {
	hash := sha256.Sum256(cert)

	f, err := os.OpenFile("/dev/attestation/user_report_data", os.O_WRONLY, 0)
	if err != nil {
		return nil, err
	}

	_, err = f.Write(hash[:])
	f.Close()
	if err != nil {
		return nil, err
	}

	f, err = os.Open("/dev/attestation/quote")
	if err != nil {
		return nil, err
	}

	quote := make([]byte, 8192)
	quoteSize, err := f.Read(quote)
	f.Close()
	if err != nil {
		return nil, err
	}

	if !(0 < quoteSize && quoteSize < len(quote)) {
		return nil, errors.New("invalid quote size")
	}

	// add OE header to raw quote
	quoteHeader := make([]byte, 16)
	binary.LittleEndian.PutUint32(quoteHeader, 1)     // version
	binary.LittleEndian.PutUint32(quoteHeader[4:], 2) // OE_REPORT_TYPE_SGX_REMOTE
	binary.LittleEndian.PutUint64(quoteHeader[8:], uint64(quoteSize))
	return append(quoteHeader, quote[:quoteSize]...), nil
}
