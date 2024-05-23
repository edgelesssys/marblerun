// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package attestation

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"testing"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/stretchr/testify/assert"
)

func TestVerifyCertificate(t *testing.T) {
	testCert := &x509.Certificate{
		Raw: []byte("cert"),
	}
	quoteData := sha256.Sum256(testCert.Raw)
	defaultConfig := Config{
		SecurityVersion: 2,
		ProductID:       3,
		SignerID:        "ABCD",
	}
	defaultReport := attestation.Report{
		Data:            quoteData[:],
		SecurityVersion: 2,
		ProductID:       []byte{0x03, 0x00},
		SignerID:        []byte{0xAB, 0xCD},
	}

	testCases := map[string]struct {
		config     Config
		verify     func([]byte) (attestation.Report, error)
		wantErr    bool
		wantTCBErr bool
	}{
		"success": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return defaultReport, nil
			},
		},
		"success with nonce": {
			config: func() Config {
				config := defaultConfig
				config.Nonce = []byte{0x01, 0x02}
				return config
			}(),
			verify: func([]byte) (attestation.Report, error) {
				quoteData := sha256.Sum256(append(testCert.Raw, []byte{0x01, 0x02}...))
				report := defaultReport
				report.Data = quoteData[:]
				return report, nil
			},
		},
		"verify fails": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return defaultReport, assert.AnError
			},
			wantErr: true,
		},
		"invalid hash": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            make([]byte, 64),
					SecurityVersion: 2,
					ProductID:       []byte{0x03, 0x00},
					SignerID:        []byte{0xAB, 0xCD},
				}, nil
			},
			wantErr: true,
		},
		"older SecurityVersion": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            quoteData[:],
					SecurityVersion: 1,
					ProductID:       []byte{0x03, 0x00},
					SignerID:        []byte{0xAB, 0xCD},
				}, nil
			},
			wantErr: true,
		},
		"newer SecurityVersion": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            quoteData[:],
					SecurityVersion: 3,
					ProductID:       []byte{0x03, 0x00},
					SignerID:        []byte{0xAB, 0xCD},
				}, nil
			},
		},
		"invalid ProductID": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            quoteData[:],
					SecurityVersion: 2,
					ProductID:       []byte{0x04, 0x00},
					SignerID:        []byte{0xAB, 0xCD},
				}, nil
			},
			wantErr: true,
		},
		"invalid SignerID": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            quoteData[:],
					SecurityVersion: 2,
					ProductID:       []byte{0x03, 0x00},
					SignerID:        []byte{0xAB, 0xCE},
				}, nil
			},
			wantErr: true,
		},
		"missing config ProductID": {
			config: Config{
				SecurityVersion: 2,
				SignerID:        "ABCD",
			},
			verify: func([]byte) (attestation.Report, error) {
				return defaultReport, nil
			},
			wantErr: true,
		},
		"missing config SecurityVersion": {
			config: Config{ProductID: 3, SignerID: "ABCD"},
			verify: func([]byte) (attestation.Report, error) {
				return defaultReport, nil
			},
			wantErr: true,
		},
		"only config uniqueID": {
			config: Config{UniqueID: "ABCD"},
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:     quoteData[:],
					UniqueID: []byte{0xAB, 0xCD},
				}, nil
			},
		},
		"invalid uniqueID": {
			config: Config{UniqueID: "ABCD"},
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:     quoteData[:],
					UniqueID: []byte{0xAB, 0xCE},
				}, nil
			},
			wantErr: true,
		},
		"debug enclave not allowed": {
			config: Config{UniqueID: "ABCD"},
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:     quoteData[:],
					UniqueID: []byte{0xAB, 0xCD},
					Debug:    true,
				}, nil
			},
			wantErr: true,
		},
		"debug enclave allowed": {
			config: Config{UniqueID: "ABCD", Debug: true},
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:     quoteData[:],
					UniqueID: []byte{0xAB, 0xCD},
					Debug:    true,
				}, nil
			},
		},
		"tcb error": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            quoteData[:],
					SecurityVersion: 2,
					ProductID:       []byte{0x03, 0x00},
					SignerID:        []byte{0xAB, 0xCD},
					TCBStatus:       tcbstatus.OutOfDate,
				}, attestation.ErrTCBLevelInvalid
			},
			wantErr:    true,
			wantTCBErr: true,
		},
		"tcb error and invalid product": {
			config: defaultConfig,
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            quoteData[:],
					SecurityVersion: 2,
					ProductID:       []byte{0x04, 0x00},
					SignerID:        []byte{0xAB, 0xCD},
					TCBStatus:       tcbstatus.OutOfDate,
				}, attestation.ErrTCBLevelInvalid
			},
			wantErr: true,
		},
		"tcb error accepted": {
			config: func() Config {
				config := defaultConfig
				config.AcceptedTCBStatuses = []string{"OutOfDate"}
				return config
			}(),
			verify: func([]byte) (attestation.Report, error) {
				return attestation.Report{
					Data:            quoteData[:],
					SecurityVersion: 2,
					ProductID:       []byte{0x03, 0x00},
					SignerID:        []byte{0xAB, 0xCD},
					TCBStatus:       tcbstatus.OutOfDate,
				}, attestation.ErrTCBLevelInvalid
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			out := &bytes.Buffer{}
			err := verifyCertificate(out, testCert, []byte{}, tc.config, tc.verify)

			if tc.wantErr {
				assert.Error(err)

				if tc.wantTCBErr {
					var tcbErr *TCBStatusError
					assert.ErrorAs(err, &tcbErr)
				}

				return
			}

			assert.NoError(err)
			if tc.config.AcceptedTCBStatuses != nil {
				accepted := false
				for _, status := range tc.config.AcceptedTCBStatuses {
					if strings.Contains(out.String(), status) {
						accepted = true
						break
					}
				}
				assert.True(accepted)
			}
		})
	}
}
