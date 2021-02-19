package main

// #include <spawn.h>
// #include <sys/wait.h>
import "C"

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/marble/premain"
	"github.com/spf13/afero"
	"google.golang.org/grpc/credentials"
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
	if err := premain.PreMainEx(quoteIssuer{}, activate, hostfs, hostfs); err != nil {
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

func activate(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error) {
	// call the actual Activate function
	params, err := premain.ActivateRPC(req, coordAddr, tlsCredentials)
	if err != nil {
		return nil, err
	}

	// Write the protected files key if present. We must do this "manually" here because premain will write files
	// in an unspecified order. However, the key must be written before any other protected file is written.
	const pfKeyPath = "/dev/attestation/protected_files_key"
	if key, ok := params.Files[pfKeyPath]; ok {
		if err := ioutil.WriteFile(pfKeyPath, []byte(key), 0); err != nil {
			return nil, err
		}
	}

	return params, nil
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
