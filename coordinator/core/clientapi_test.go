// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustSetup() (*Core, *manifest.Manifest) {
	var manifest manifest.Manifest
	if err := json.Unmarshal([]byte(test.ManifestJSON), &manifest); err != nil {
		panic(err)
	}
	return NewCoreWithMocks(), &manifest
}

func TestGetManifestSignature(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSON))

	assert.NoError(err)

	sigECDSA, hash, manifest := c.GetManifestSignature(context.TODO())
	expectedHash := sha256.Sum256([]byte(test.ManifestJSON))
	assert.Equal(expectedHash[:], hash)
	rootPrivK, err := c.data.getPrivK(sKCoordinatorRootKey)
	assert.NoError(err)
	assert.True(ecdsa.VerifyASN1(&rootPrivK.PublicKey, expectedHash[:], sigECDSA))
	assert.Equal([]byte(test.ManifestJSON), manifest)
}

func TestSetManifest(t *testing.T) {
	assert := assert.New(t)

	c, manifest := mustSetup()
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.NoError(err, "SetManifest should succed on first try")
	cManifest, err := c.data.getManifest()
	assert.NoError(err)
	assert.Equal(*manifest, cManifest, "Manifest should be set correctly")

	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.Error(err, "SetManifest should fail on the second try")
	cManifest, err = c.data.getManifest()
	assert.NoError(err)
	assert.Equal(*manifest, cManifest, "Manifest should still be set correctly")

	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON)[:len(test.ManifestJSON)-1])
	assert.Error(err, "SetManifest should fail on broken json")
	cManifest, err = c.data.getManifest()
	assert.NoError(err)
	assert.Equal(*manifest, cManifest, "Manifest should still be set correctly")

	// use new core
	c, _ = mustSetup()
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON)[:len(test.ManifestJSON)-1])
	assert.Error(err, "SetManifest should fail on broken json")
	c, _ = mustSetup()
	_, err = c.SetManifest(context.TODO(), []byte(""))
	assert.Error(err, "empty string should not be accepted")

	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.NoError(err, "SetManifest should succed after failed tries")
	cManifest, err = c.data.getManifest()
	assert.NoError(err)
	assert.Equal(*manifest, cManifest, "Manifest should be set correctly")
}

func TestSetManifestInvalid(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// try setting manifest with unallowed marble package, but proper json
	c, manifest := mustSetup()
	// get any element of the map
	for _, marble := range manifest.Marbles {
		marble.Package = "foo"
		manifest.Marbles["bar"] = marble
		break
	}
	modRawManifest, err := json.Marshal(manifest)
	require.NoError(err)
	_, err = c.SetManifest(context.TODO(), modRawManifest)
	assert.Equal("manifest does not contain marble package foo", err.Error())

	// Try setting manifest with all values unset, no debug mode (this should fail)
	c, manifest = mustSetup()

	backendPackage := manifest.Packages["backend"]
	backendPackage.Debug = false
	backendPackage.UniqueID = ""
	backendPackage.SignerID = ""
	backendPackage.ProductID = nil
	backendPackage.SecurityVersion = nil

	manifest.Packages["backend"] = backendPackage
	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = c.SetManifest(context.TODO(), modRawManifest)
	assert.Equal("manifest misses value for SignerID in package backend", err.Error())

	// Enable debug mode, should work now
	c = testManifestInvalidDebugCase(c, manifest, backendPackage, assert, require)

	// Set SignerID, now should complain about missing ProductID
	backendPackage.SignerID = "some signer"
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = c.SetManifest(context.TODO(), modRawManifest)
	assert.Equal("manifest misses value for ProductID in package backend", err.Error())

	// Enable debug mode, should work now
	c = testManifestInvalidDebugCase(c, manifest, backendPackage, assert, require)

	// Set ProductID, now should complain about missing SecurityVersion
	productIDValue := uint64(42)
	backendPackage.ProductID = &productIDValue
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = c.SetManifest(context.TODO(), modRawManifest)
	assert.Equal("manifest misses value for SecurityVersion in package backend", err.Error())

	// Enable debug mode, should work now
	c = testManifestInvalidDebugCase(c, manifest, backendPackage, assert, require)

	// Set SecurityVersion, now we should pass
	securityVersion := uint(1)
	backendPackage.SecurityVersion = &securityVersion
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = c.SetManifest(context.TODO(), modRawManifest)
	assert.NoError(err)

	// Reset & enable debug mode, should also work now
	c, _ = mustSetup()
	c = testManifestInvalidDebugCase(c, manifest, backendPackage, assert, require)

	// Try setting manifest with UniqueID + other value set, this should fail again
	backendPackage.UniqueID = "something unique"
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = c.SetManifest(context.TODO(), modRawManifest)
	assert.Equal("manifest specfies both UniqueID *and* SignerID/ProductID/SecurityVersion in package backend", err.Error())

	// Enable debug mode, should work now
	_ = testManifestInvalidDebugCase(c, manifest, backendPackage, assert, require)
}

func TestManifestTemplateChecks(t *testing.T) {
	missingSecret := []byte(`{
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"Debug": false
		}
	},
	"Marbles": {
		"backend_first": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Files": {
					"/tmp/defg.txt": "{{ hex .Secrets.foo }}"
				}
			}
		}
	},
	"Secrets": {
		"bar": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		}
	}
}`)
	wrongType := []byte(`{
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"Debug": false
		}
	},
	"Marbles": {
		"backend_first": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Files": {
					"/tmp/defg.txt": "{{ pem .Secrets.foo }}"
				}
			}
		}
	},
	"Secrets": {
		"foo": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		}
	}
}`)
	rawInEnv := []byte(`{
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"Debug": false
		}
	},
	"Marbles": {
		"backend_first": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Env": {
					"RAW_VAR": "{{ raw .Secrets.foo }}",
					"API_KEY": "{{ raw .Secrets.apiKey }}"
				}
			}
		}
	},
	"Secrets": {
		"foo": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"apiKey": {
			"Type": "plain",
			"UserDefined": true
		}
	}
}`)
	nullByte := []byte(`{
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"Debug": false
		}
	},
	"Marbles": {
		"backend_first": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Env": {
					"NULL_VAR": {
						"Encoding": "base64",
						"Data": "AE1hcmJsZQBSdW4A"
					}
				}
			}
		}
	}
}`)
	assert := assert.New(t)

	c := NewCoreWithMocks()
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	assert.NoError(err)

	c = NewCoreWithMocks()
	_, err = c.SetManifest(context.TODO(), missingSecret)
	assert.Error(err)

	c = NewCoreWithMocks()
	_, err = c.SetManifest(context.TODO(), wrongType)
	assert.Error(err)

	c = NewCoreWithMocks()
	_, err = c.SetManifest(context.TODO(), rawInEnv)
	assert.Error(err)

	c = NewCoreWithMocks()
	_, err = c.SetManifest(context.TODO(), nullByte)
	assert.Error(err)
}

func TestGetCertQuote(t *testing.T) {
	assert := assert.New(t)

	c, _ := mustSetup()

	cert, _, err := c.GetCertQuote(context.TODO())
	assert.NoError(err, "GetCertQuote should not fail (without manifest)")
	assert.Contains(cert, "-----BEGIN CERTIFICATE-----", "simple format check")

	c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	_, _, err = c.GetCertQuote(context.TODO())
	assert.NoError(err, "GetCertQuote should not fail (with manifest)")

	assert.NoError(c.data.putState(stateRecovery))
	_, _, err = c.GetCertQuote(context.TODO())
	assert.NoError(err, "GetCertQuote should not fail when coordinator is in recovery mode")
	// todo check quote
}

func TestGetStatus(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := mustSetup()

	// Server should be ready to accept a manifest after initializing a mock core
	statusCode, status, err := c.GetStatus(context.TODO())
	assert.NoError(err, "GetStatus failed")
	assert.EqualValues(stateAcceptingManifest, statusCode, "We should be ready to accept a manifest now, but GetStatus does tell us we don't.")
	assert.NotEmpty(status, "Status string was empty, but should not.")

	// Set a manifest, state should change
	_, err = c.SetManifest(context.TODO(), []byte(test.ManifestJSON))
	require.NoError(err)
	statusCode, status, err = c.GetStatus(context.TODO())
	assert.NoError(err, "GetStatus failed")
	assert.EqualValues(stateAcceptingMarbles, statusCode, "We should be ready to accept Marbles now, but GetStatus does tell us we don't.")
	assert.NotEmpty(status, "Status string was empty, but should not.")
}

func TestVerifyUser(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := mustSetup()

	adminTestCert, otherTestCert := test.MustSetupTestCerts(test.RecoveryPrivateKey)

	// Set a manifest containing an admin certificate
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	// Put certificates in slice, as Go's TLS library passes them in an HTTP request
	adminTestCertSlice := []*x509.Certificate{adminTestCert}
	otherTestCertSlice := []*x509.Certificate{otherTestCert}

	// Check if the adminTest certificate is deemed valid (stored in core), and the freshly generated one is deemed false
	user, err := c.VerifyUser(context.TODO(), adminTestCertSlice)
	assert.NoError(err)
	assert.Equal(*user.Certificate(), *adminTestCert)
	_, err = c.VerifyUser(context.TODO(), otherTestCertSlice)
	assert.Error(err)
	_, err = c.VerifyUser(context.TODO(), nil)
	assert.Error(err)
}

func TestUpdateManifest(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := mustSetup()

	// Set manifest
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	admin, err := c.data.getUser("admin")
	require.NoError(err)

	// Get current certificate
	rootCABeforeUpdate, err := c.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)
	intermediateCABeforeUpdate, err := c.data.getCertificate(skCoordinatorIntermediateCert)
	assert.NoError(err)
	marbleRootCABeforeUpdate, err := c.data.getCertificate(sKMarbleRootCert)
	assert.NoError(err)
	secretsBeforeUpdate, err := c.data.getSecretMap()
	assert.NoError(err)

	// Update manifest
	err = c.UpdateManifest(context.TODO(), []byte(test.UpdateManifest), admin)
	require.NoError(err)

	// Get new certificates
	rootCAAfterUpdate, err := c.data.getCertificate(sKCoordinatorRootCert)
	assert.NoError(err)
	intermediateCAAfterUpdate, err := c.data.getCertificate(skCoordinatorIntermediateCert)
	assert.NoError(err)
	marbleRootCABeAfterUpdate, err := c.data.getCertificate(sKMarbleRootCert)
	assert.NoError(err)
	secretsAfterUpdate, err := c.data.getSecretMap()
	assert.NoError(err)

	// Check if root certificate stayed the same, but intermediate CAs changed
	assert.Equal(rootCABeforeUpdate, rootCAAfterUpdate)
	assert.NotEqual(intermediateCABeforeUpdate, intermediateCAAfterUpdate)
	assert.NotEqual(marbleRootCABeforeUpdate, marbleRootCABeAfterUpdate)

	// Secrets: symmetric keys should remain the same, certificates should be regenerated based on the new intermediate ca
	assert.Equal(secretsBeforeUpdate["symmetricKeyShared"], secretsAfterUpdate["symmetricKeyShared"])
	assert.NotEqual(secretsBeforeUpdate["certShared"], secretsAfterUpdate["certShared"])

	// Verify if the old secret certificate is not correctly verified anymore by the new intermediate certificate
	roots := x509.NewCertPool()
	roots.AddCert(intermediateCAAfterUpdate)

	opts := x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	oldCert := x509.Certificate(secretsBeforeUpdate["certShared"].Cert)
	_, err = oldCert.Verify(opts)
	assert.Error(err)
	newCert := x509.Certificate(secretsAfterUpdate["certShared"].Cert)
	_, err = newCert.Verify(opts)
	assert.NoError(err)

	// Verify if the old secret certificate is not correctly verified anymore by the new marbleRoot certificate
	roots = x509.NewCertPool()
	roots.AddCert(marbleRootCABeAfterUpdate)
	opts = x509.VerifyOptions{
		Roots:     roots,
		DNSName:   "localhost",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	_, err = oldCert.Verify(opts)
	assert.Error(err)
	_, err = newCert.Verify(opts)
	assert.NoError(err)

	// updating the manifest should have produced an entry for "frontend" in the updatelog
	updateLog, err := c.GetUpdateLog(context.TODO())
	assert.NoError(err)
	assert.Contains(updateLog, `"package":"frontend"`)
}

func TestUpdateManifestInvalid(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := mustSetup()

	// Good update manifests
	// Set manifest (frontend has SecurityVersion 3)
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	cPackage, err := c.data.getPackage("frontend")
	assert.NoError(err)
	assert.EqualValues(3, *cPackage.SecurityVersion)

	// Try to update with unregistered user
	someUser := user.NewUser("invalid", nil)
	err = c.UpdateManifest(context.TODO(), []byte(test.UpdateManifest), someUser)
	assert.Error(err)

	admin, err := c.data.getUser("admin")
	assert.NoError(err)

	// Try to update manifest (frontend's SecurityVersion should rise from 3 to 5)
	err = c.UpdateManifest(context.TODO(), []byte(test.UpdateManifest), admin)
	require.NoError(err)
	cUpdatedPackage, err := c.data.getPackage("frontend")
	assert.NoError(err)
	assert.EqualValues(5, *cUpdatedPackage.SecurityVersion)

	// Test invalid manifests
	var badUpdateManifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.UpdateManifest), &badUpdateManifest))

	// Add non existing package, should fail
	badUpdateManifest.Packages["nonExisting"] = badUpdateManifest.Packages["frontend"]
	badRawManifest, err := json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(context.TODO(), badRawManifest, admin)
	assert.Error(err)

	delete(badUpdateManifest.Packages, "nonExisting")

	// Test if we cannot enable debug (and thus potentially bypass all these parameters)
	badModPackage := badUpdateManifest.Packages["frontend"]
	badModPackage.Debug = true
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(context.TODO(), badRawManifest, admin)
	assert.Error(err)

	badModPackage.Debug = false

	// Test if no SecurityVersion is defined
	badModPackage.SecurityVersion = nil
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(context.TODO(), badRawManifest, admin)
	assert.Error(err)

	// Test if downgrading fails
	// Alter test update manifest to set the SecurityVersion to '2', which is lower than both, original and update manifest
	badSecurityVersion := uint(2)
	badModPackage.SecurityVersion = &badSecurityVersion
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(context.TODO(), badRawManifest, admin)
	assert.Error(err)

	// Test if downgrading fails
	// Generate a new manifest with SecurityVersion 4, which is higher than the original manifest, but lower than the currently set update manifest (which encorces level 5)
	badSecurityVersion = uint(4)
	badModPackage.SecurityVersion = &badSecurityVersion
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(context.TODO(), badRawManifest, admin)
	assert.Error(err)

	// Test if removing a package from a currently existing update manifest fails
	badUpdateManifest.Packages["backend"] = badModPackage
	delete(badUpdateManifest.Packages, "frontend")
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(context.TODO(), badRawManifest, admin)
	assert.Error(err)

	// Test what happens if no packages are defined at all
	badUpdateManifest.Packages = nil
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(context.TODO(), badRawManifest, admin)
	assert.Error(err)
}

func TestGetSecret(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := mustSetup()
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	symmetricSecret := "symmetricKeyShared"
	certSecret := "certShared"
	secret1, err := c.data.getSecret(symmetricSecret)
	assert.NoError(err)
	secret2, err := c.data.getSecret(certSecret)
	assert.NoError(err)
	admin, err := c.data.getUser("admin")
	assert.NoError(err)

	// requested secrets should be the same
	reqSecrets, err := c.GetSecrets(context.TODO(), []string{symmetricSecret, certSecret}, admin)
	assert.NoError(err)
	assert.True(len(reqSecrets) == 2)
	assert.Equal(secret1, reqSecrets[symmetricSecret])
	assert.Equal(secret2, reqSecrets[certSecret])

	// request should fail if the user lacks permissions
	_, err = c.GetSecrets(context.TODO(), []string{symmetricSecret, "restrictedSecret"}, admin)
	assert.Error(err)

	// requesting an secret should return an empty secret since it was not set
	sec, err := c.GetSecrets(context.TODO(), []string{"symmetricKeyUnset"}, admin)
	assert.NoError(err)
	assert.Empty(sec["symmetricKeyUnset"].Public)
	assert.Empty(sec["symmetricKeyUnset"].Private)
}

func TestWriteSecret(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := mustSetup()
	_, err := c.SetManifest(context.TODO(), []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	admin, err := c.data.getUser("admin")
	assert.NoError(err)
	symmetricSecret := "symmetricKeyUnset"
	certSecret := "certUnset"

	// there should be no initialized secret yet
	sec, err := c.data.getSecret(symmetricSecret)
	assert.NoError(err)
	assert.Empty(sec.Public)
	assert.Empty(sec.Private)
	assert.Empty(sec.Cert)
	sec, err = c.data.getSecret(certSecret)
	assert.NoError(err)
	assert.Empty(sec.Public)
	assert.Empty(sec.Private)

	// set a secret
	err = c.WriteSecrets(context.TODO(), []byte(test.UserSecrets), admin)
	assert.NoError(err)
	secret, err := c.data.getSecret(symmetricSecret)
	assert.NoError(err)
	assert.Equal(16, len(secret.Public))
	secret, err = c.data.getSecret(certSecret)
	assert.NoError(err)
	assert.Equal("MarbleRun Coordinator - Intermediate CA", secret.Cert.Issuer.CommonName)

	// try to set a secret in plain format
	genericSecret := []byte(`{
		"genericSecret": {
			"Key": "` + base64.StdEncoding.EncodeToString([]byte("MarbleRun Unit Test")) + `"
		}
	}`)
	err = c.WriteSecrets(context.TODO(), genericSecret, admin)
	assert.NoError(err)
	secret, err = c.data.getSecret("genericSecret")
	assert.NoError(err)
	assert.Equal("MarbleRun Unit Test", string(secret.Public))

	// try to set a secret with NULL bytes
	genericSecret = []byte(`{
		"genericSecret": {
			"Key": "` + base64.StdEncoding.EncodeToString([]byte{0x41, 0x41, 0x00, 0x41}) + `"
		}
	}`)
	err = c.WriteSecrets(context.TODO(), genericSecret, admin)
	assert.Error(err)

	// try to set a secret incorrect size
	invalidSecret := []byte(`{
		"symmetricKeyUnset": {
			"Key": "` + base64.StdEncoding.EncodeToString([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) + `"
		}	
	}`)
	err = c.WriteSecrets(context.TODO(), invalidSecret, admin)
	assert.Error(err)

	// make sure meta data of private secrets was saved correctly
	secrets, err := c.data.getSecretMap()
	assert.NoError(err)
	priv := make(map[string]manifest.Secret)
	for k, v := range secrets {
		if !v.Shared && !v.UserDefined {
			priv[k] = v
		}
	}
	pC, _ := c.data.getCertificate(sKMarbleRootCert)
	pK, _ := c.data.getPrivK(sKCoordinatorIntermediateKey)
	priv, err = c.generateSecrets(context.TODO(), priv, uuid.New(), pC, pK)
	assert.NoError(err)
	assert.Equal("MarbleRun Unit Test Private", priv["certPrivate"].Cert.Subject.CommonName)
}

func testManifestInvalidDebugCase(c *Core, manifest *manifest.Manifest, marblePackage quote.PackageProperties, assert *assert.Assertions, require *require.Assertions) *Core {
	marblePackage.Debug = true
	manifest.Packages["backend"] = marblePackage

	modRawManifest, err := json.Marshal(manifest)
	require.NoError(err)
	_, err = c.SetManifest(context.TODO(), modRawManifest)
	assert.NoError(err)
	marblePackage.Debug = false

	// Since debug case should pass, return a resetted fresh core
	c, _ = mustSetup()
	return c
}
