//go:build integration && pkcs11

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package pkcs11

import (
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"flag"
	"testing"
	"time"

	"github.com/ThalesGroup/crypto11"
	"github.com/edgelesssys/marblerun/util"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var configPath = flag.String("pkcs11-config", "", "path to PKCS#11 configuration file")

func TestLoadX509KeyPair(t *testing.T) {
	// Ensure we can load the PKCS#11 configuration file
	pkcs11, err := crypto11.ConfigureFromFile(*configPath)
	require.NoError(t, err)
	require.NoError(t, pkcs11.Close())

	testCases := map[string]struct {
		init    func(t *testing.T) (keyID, keyLabel, certID, certLabel string)
		wantErr bool
	}{
		"identified by ID and label": {
			init: func(t *testing.T) (keyID, keyLabel, certID, certLabel string) {
				t.Helper()
				require := require.New(t)
				prefix := uuid.New().String()
				keyID, keyLabel, certID, certLabel = prefix+"keyID", prefix+"keyLabel", prefix+"certID", prefix+"certLabel"
				pkcs11, err := crypto11.ConfigureFromFile(*configPath)
				require.NoError(err)
				defer pkcs11.Close()
				privK, err := pkcs11.GenerateECDSAKeyPairWithLabel([]byte(keyID), []byte(keyLabel), elliptic.P256())
				require.NoError(err)
				cert, err := createSelfSignedCertificate(privK)
				require.NoError(err)
				require.NoError(pkcs11.ImportCertificateWithLabel([]byte(certID), []byte(certLabel), cert))
				return keyID, keyLabel, certID, certLabel
			},
		},
		"identified by ID only": {
			init: func(t *testing.T) (keyID, keyLabel, certID, certLabel string) {
				t.Helper()
				require := require.New(t)
				prefix := uuid.New().String()
				keyID, keyLabel, certID, certLabel = prefix+"keyID", prefix+"keyLabel", prefix+"certID", prefix+"certLabel"
				pkcs11, err := crypto11.ConfigureFromFile(*configPath)
				require.NoError(err)
				defer pkcs11.Close()
				privK, err := pkcs11.GenerateECDSAKeyPair([]byte(keyID), elliptic.P256())
				require.NoError(err)
				cert, err := createSelfSignedCertificate(privK)
				require.NoError(err)
				require.NoError(pkcs11.ImportCertificate([]byte(certID), cert))
				return keyID, "", certID, ""
			},
		},
		"identified by label only": {
			init: func(t *testing.T) (keyID, keyLabel, certID, certLabel string) {
				t.Helper()
				require := require.New(t)
				prefix := uuid.New().String()
				keyID, keyLabel, certID, certLabel = prefix+"keyID", prefix+"keyLabel", prefix+"certID", prefix+"certLabel"
				pkcs11, err := crypto11.ConfigureFromFile(*configPath)
				require.NoError(err)
				defer pkcs11.Close()
				privK, err := pkcs11.GenerateECDSAKeyPairWithLabel([]byte(keyID), []byte(keyLabel), elliptic.P256())
				require.NoError(err)
				cert, err := createSelfSignedCertificate(privK)
				require.NoError(err)
				require.NoError(pkcs11.ImportCertificateWithLabel([]byte(certID), []byte(certLabel), cert))
				return "", keyLabel, "", certLabel
			},
		},
		"key not found": {
			init: func(t *testing.T) (keyID, keyLabel, certID, certLabel string) {
				t.Helper()
				require := require.New(t)
				prefix := uuid.New().String()
				keyID, keyLabel, certID, certLabel = prefix+"keyID", prefix+"keyLabel", prefix+"certID", prefix+"certLabel"
				pkcs11, err := crypto11.ConfigureFromFile(*configPath)
				require.NoError(err)
				defer pkcs11.Close()
				privK, err := pkcs11.GenerateECDSAKeyPairWithLabel([]byte(keyID), []byte(keyLabel), elliptic.P256())
				require.NoError(err)
				cert, err := createSelfSignedCertificate(privK)
				require.NoError(err)
				require.NoError(pkcs11.ImportCertificateWithLabel([]byte(certID), []byte(certLabel), cert))
				return "not-found", "not-found", certID, certLabel
			},
			wantErr: true,
		},
		"cert not found": {
			init: func(t *testing.T) (keyID, keyLabel, certID, certLabel string) {
				t.Helper()
				require := require.New(t)
				prefix := uuid.New().String()
				keyID, keyLabel, certID, certLabel = prefix+"keyID", prefix+"keyLabel", prefix+"certID", prefix+"certLabel"
				pkcs11, err := crypto11.ConfigureFromFile(*configPath)
				require.NoError(err)
				defer pkcs11.Close()
				_, err = pkcs11.GenerateECDSAKeyPairWithLabel([]byte(keyID), []byte(keyLabel), elliptic.P256())
				require.NoError(err)
				return keyID, keyLabel, certID, certLabel
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			keyID, keyLabel, certID, certLabel := tc.init(t)
			crt, cancel, err := LoadX509KeyPair(*configPath, keyID, keyLabel, certID, certLabel)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			require.NoError(err)
			defer func() {
				_ = cancel()
			}()

			assert.NotNil(crt.PrivateKey)
			assert.NotNil(crt.Certificate)
			assert.NotNil(crt.Leaf)

			require.Len(crt.Certificate, 1)
			leafCrt, err := x509.ParseCertificate(crt.Certificate[0])
			require.NoError(err)
			assert.True(crt.Leaf.Equal(leafCrt))

			privK, ok := crt.PrivateKey.(crypto.Signer)
			require.True(ok)
			pubK, ok := privK.Public().(interface{ Equal(crypto.PublicKey) bool })
			require.True(ok)
			assert.True(pubK.Equal(crt.Leaf.PublicKey))
		})
	}
}

func createSelfSignedCertificate(priv crypto.Signer) (*x509.Certificate, error) {
	serialNumber, err := util.GenerateCertificateSerialNumber()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		NotBefore:    now.Add(-2 * time.Hour),
		NotAfter:     now.Add(2 * time.Hour),
	}
	cert, err := x509.CreateCertificate(rand.Reader, template, template, priv.Public(), priv)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(cert)
}
