package certificates

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// TLSFromDER converts an DER certificate to TLS format
func TLSFromDER(certDER []byte, privk interface{}) (*tls.Certificate, error) {
	// DER -> PEM -> TLS seems to be the only viable conversion here, somewhat cumbersome...
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if certPEM == nil {
		return nil, errors.New("failed to encode certificate as PEM")
	}
	privkPKCS8, err := x509.MarshalPKCS8PrivateKey(privk)
	if err != nil {
		return nil, err
	}
	privkPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privkPKCS8})
	if privkPEM == nil {
		return nil, errors.New("failed to encode privk as PEM")
	}
	certTLS, err := tls.X509KeyPair(certPEM, privkPEM)
	if err != nil {
		return nil, err
	}
	return &certTLS, nil
}
