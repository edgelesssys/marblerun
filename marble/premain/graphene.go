package premain

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io/ioutil"
	"os"

	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"google.golang.org/grpc/credentials"
)

// GrapheneActivate sends an activation request to the Coordinator and initializes protected files.
func GrapheneActivate(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error) {
	// call the actual Activate function
	params, err := ActivateRPC(req, coordAddr, tlsCredentials)
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

// GrapheneQuoteIssuer issues quotes
type GrapheneQuoteIssuer struct{}

// Issue issues a quote for remote attestation for a given message
func (GrapheneQuoteIssuer) Issue(cert []byte) ([]byte, error) {
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
