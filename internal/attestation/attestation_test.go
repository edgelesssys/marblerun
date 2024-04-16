// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attestation

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type generalResponse struct {
	Status  string      `json:"status"`
	Data    interface{} `json:"data"`
	Message string      `json:"message,omitempty"` // only used when status = "error"
}

func TestGetCertificate(t *testing.T) {
	signerConfig := Config{
		SecurityVersion: 2,
		ProductID:       3,
		SignerID:        "ABCD",
	}

	signerReport := &attestation.Report{
		SecurityVersion: 2,
		ProductID:       []byte{0x03, 0x00},
		SignerID:        []byte{0xAB, 0xCD},
	}

	testCases := map[string]struct {
		nonce      []byte
		config     Config
		report     *attestation.Report
		verifyErr  error
		wantErr    bool
		wantTCBErr bool
		tcbStatus  tcbstatus.Status
	}{
		"get certificate without quote validation": {},
		"get certificate with quote validation": {
			config: signerConfig,
			report: signerReport,
		},
		"get certificate with quote validation and nonce": {
			config: signerConfig,
			report: signerReport,
			nonce:  []byte{0x01, 0x02, 0x03},
		},
		"verify fails": {
			config:    signerConfig,
			report:    signerReport,
			verifyErr: assert.AnError,
			wantErr:   true,
		},
		"invalid hash": {
			config: signerConfig,
			report: &attestation.Report{
				Data:            make([]byte, 64),
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
			wantErr: true,
		},
		"invalid security version": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 1,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
			wantErr: true,
		},
		"newer security version": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 3,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
		},
		"invalid product": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 2,
				ProductID:       []byte{0x04, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			},
			wantErr: true,
		},
		"invalid signer": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCE},
			},
			wantErr: true,
		},
		"missing productID": {
			config:  Config{SecurityVersion: 2, SignerID: "ABCD"},
			report:  signerReport,
			wantErr: true,
		},
		"missing securityVersion": {
			config:  Config{ProductID: 3, SignerID: "ABCD"},
			report:  signerReport,
			wantErr: true,
		},
		"uniqeID": {
			config: Config{UniqueID: "ABCD"},
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCD},
			},
		},
		"invalid uniqeID": {
			config: Config{UniqueID: "ABCD"},
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCE},
			},
			wantErr: true,
		},
		"debug enclave not allowed": {
			config: Config{UniqueID: "ABCD"},
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCD},
				Debug:    true,
			},
			wantErr: true,
		},
		"debug enclave allowed": {
			config: Config{UniqueID: "ABCD", Debug: true},
			report: &attestation.Report{
				UniqueID: []byte{0xAB, 0xCD},
				Debug:    true,
			},
		},
		"tcb error": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
				TCBStatus:       tcbstatus.OutOfDate,
			},
			verifyErr:  attestation.ErrTCBLevelInvalid,
			wantTCBErr: true,
			tcbStatus:  tcbstatus.OutOfDate,
		},
		"tcb error and invalid product": {
			config: signerConfig,
			report: &attestation.Report{
				SecurityVersion: 2,
				ProductID:       []byte{0x04, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
				TCBStatus:       tcbstatus.OutOfDate,
			},
			verifyErr: attestation.ErrTCBLevelInvalid,
			wantErr:   true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			var quote []byte
			var cert string

			server, addr, expectedCert := newServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal("/quote", r.RequestURI)
				writeJSON(w, certQuoteResp{cert, quote})
			}))
			defer server.Close()

			cert = expectedCert
			block, _ := pem.Decode([]byte(cert))
			certRaw := block.Bytes
			hash := sha256.Sum256(append(certRaw, tc.nonce...))
			quote = hash[:]

			var verify verifyFunc
			if tc.report != nil {
				verify = func(reportBytes []byte) (attestation.Report, error) {
					assert.Equal(quote, reportBytes)
					report := *tc.report
					if report.Data == nil {
						report.Data = hash[:]
					}
					return report, tc.verifyErr
				}
			}

			actualCerts, tcbStatus, _, err := getCertificate(context.Background(), addr, tc.nonce, tc.config, verify)
			if tc.wantTCBErr {
				require.Equal(attestation.ErrTCBLevelInvalid, err)
				assert.Equal(tc.tcbStatus, tcbStatus)
			} else if tc.wantErr {
				assert.Error(err)
				assert.NotErrorIs(err, attestation.ErrTCBLevelInvalid)
				return
			} else {
				require.NoError(err)
			}

			assert.EqualValues(expectedCert, pem.EncodeToMemory(actualCerts[0]))
		})
	}
}

func TestGetMultipleCertificates(t *testing.T) {
	config := Config{
		SecurityVersion: 2,
		ProductID:       3,
		SignerID:        "ABCD",
	}

	assert := assert.New(t)
	var quote []byte
	var certs string

	server, addr, expectedCerts := newServerMultipleCertificates(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/quote", r.RequestURI)
		writeJSON(w, certQuoteResp{certs, quote})
	}))
	certs = expectedCerts[0] + expectedCerts[1]
	block, _ := pem.Decode([]byte(expectedCerts[1])) // last one is supposed to be root CA, which we use for quoting
	certRaw := block.Bytes
	hash := sha256.Sum256(certRaw)
	quote = hash[:]

	defer server.Close()

	// get certificates without quote validation
	actualCerts, _, _, err := getCertificate(context.Background(), addr, nil, Config{}, nil)
	assert.NoError(err)
	assert.EqualValues(expectedCerts[0], pem.EncodeToMemory(actualCerts[0]))
	assert.EqualValues(expectedCerts[1], pem.EncodeToMemory(actualCerts[1]))

	// get certificates with quote validation
	actualCerts, _, _, err = getCertificate(context.Background(), addr, nil, config,
		func(reportBytes []byte) (attestation.Report, error) {
			assert.Equal(quote, reportBytes)
			return attestation.Report{
				Data:            hash[:],
				SecurityVersion: 2,
				ProductID:       []byte{0x03, 0x00},
				SignerID:        []byte{0xAB, 0xCD},
			}, nil
		})
	assert.NoError(err)
	assert.EqualValues(expectedCerts[0], pem.EncodeToMemory(actualCerts[0]))
	assert.EqualValues(expectedCerts[1], pem.EncodeToMemory(actualCerts[1]))
}

func newServer(handler http.Handler) (server *httptest.Server, addr string, cert string) {
	s := httptest.NewTLSServer(handler)
	return s, s.Listener.Addr().String(), toPEM(s.Certificate().Raw)
}

func newServerMultipleCertificates(handler http.Handler) (server *httptest.Server, addr string, certs []string) {
	// Create a second test certificate
	key, err := rsa.GenerateKey(rand.Reader, 3096)
	if err != nil {
		panic(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		IsCA:         false,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}

	testCertRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	s := httptest.NewTLSServer(handler)
	expectedCerts := []string{toPEM(testCertRaw), toPEM(s.Certificate().Raw)}
	return s, s.Listener.Addr().String(), expectedCerts
}

func toPEM(certificate []byte) string {
	result := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate})
	if len(result) <= 0 {
		panic("EncodeToMemory failed")
	}
	return string(result)
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	dataToReturn := generalResponse{Status: "success", Data: v}
	if err := json.NewEncoder(w).Encode(dataToReturn); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}
