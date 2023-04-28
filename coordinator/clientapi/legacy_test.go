// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package clientapi

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/crypto"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/recovery"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/coordinator/store/wrapper"
	"github.com/edgelesssys/marblerun/coordinator/updatelog"
	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSetManifest_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	rawManifest := []byte(test.ManifestJSON)
	var manifest manifest.Manifest
	require.NoError(json.Unmarshal(rawManifest, &manifest))

	c, getter := setupAPI(t)
	_, err := c.SetManifest(ctx, rawManifest)
	assert.NoError(err, "SetManifest should succeed on first try")
	cManifest, err := getter.GetManifest()
	assert.NoError(err)
	assert.Equal(manifest, cManifest, "Manifest should be set correctly")

	_, err = c.SetManifest(ctx, rawManifest)
	assert.Error(err, "SetManifest should fail on the second try")
	cManifest, err = getter.GetManifest()
	assert.NoError(err)
	assert.Equal(manifest, cManifest, "Manifest should still be set correctly")

	_, err = c.SetManifest(ctx, rawManifest[:len(rawManifest)-1])
	assert.Error(err, "SetManifest should fail on broken json")
	cManifest, err = getter.GetManifest()
	assert.NoError(err)
	assert.Equal(manifest, cManifest, "Manifest should still be set correctly")

	// use new core
	c, _ = setupAPI(t)
	_, err = c.SetManifest(ctx, rawManifest[:len(rawManifest)-1])
	assert.Error(err, "SetManifest should fail on broken json")

	c, getter = setupAPI(t)
	_, err = c.SetManifest(ctx, []byte(""))
	assert.Error(err, "empty string should not be accepted")

	_, err = c.SetManifest(ctx, rawManifest)
	assert.NoError(err, "SetManifest should succed after failed tries")
	cManifest, err = getter.GetManifest()
	assert.NoError(err)
	assert.Equal(manifest, cManifest, "Manifest should be set correctly")
}

func TestSetManifestInvalid_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	newTestManifest := func() *manifest.Manifest {
		rawManifest := []byte(test.ManifestJSON)
		var manifest manifest.Manifest
		require.NoError(json.Unmarshal(rawManifest, &manifest))
		return &manifest
	}

	testManifestInvalidDebugCase := func(a *ClientAPI, manifest *manifest.Manifest, marblePackage quote.PackageProperties) {
		marblePackage.Debug = true
		manifest.Packages["backend"] = marblePackage

		modRawManifest, err := json.Marshal(manifest)
		require.NoError(err)
		_, err = a.SetManifest(ctx, modRawManifest)
		assert.NoError(err)

		marblePackage.Debug = false
	}

	// try setting manifest with unallowed marble package, but proper json
	a, _ := setupAPI(t)
	manifest := newTestManifest()

	// get any element of the map
	for _, marble := range manifest.Marbles {
		marble.Package = "foo"
		manifest.Marbles["bar"] = marble
		break
	}
	modRawManifest, err := json.Marshal(manifest)
	require.NoError(err)
	_, err = a.SetManifest(ctx, modRawManifest)
	assert.ErrorContains(err, "manifest does not contain marble package foo")

	// Try setting manifest with all values unset, no debug mode (this should fail)
	a, _ = setupAPI(t)
	manifest = newTestManifest()

	backendPackage := manifest.Packages["backend"]
	backendPackage.Debug = false
	backendPackage.UniqueID = ""
	backendPackage.SignerID = ""
	backendPackage.ProductID = nil
	backendPackage.SecurityVersion = nil

	manifest.Packages["backend"] = backendPackage
	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = a.SetManifest(ctx, modRawManifest)
	assert.ErrorContains(err, "manifest misses value for SignerID in package backend")

	// Enable debug mode, should work now
	testManifestInvalidDebugCase(a, manifest, backendPackage)

	// Set SignerID, now should complain about missing ProductID
	a, _ = setupAPI(t)
	backendPackage.SignerID = "some signer"
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = a.SetManifest(ctx, modRawManifest)
	assert.ErrorContains(err, "manifest misses value for ProductID in package backend")

	// Enable debug mode, should work now
	testManifestInvalidDebugCase(a, manifest, backendPackage)

	// Set ProductID, now should complain about missing SecurityVersion
	a, _ = setupAPI(t)
	productIDValue := uint64(42)
	backendPackage.ProductID = &productIDValue
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = a.SetManifest(ctx, modRawManifest)
	assert.ErrorContains(err, "manifest misses value for SecurityVersion in package backend")

	// Enable debug mode, should work now
	testManifestInvalidDebugCase(a, manifest, backendPackage)

	// Set SecurityVersion, now we should pass
	a, _ = setupAPI(t)
	securityVersion := uint(1)
	backendPackage.SecurityVersion = &securityVersion
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = a.SetManifest(ctx, modRawManifest)
	assert.NoError(err)

	// Reset & enable debug mode, should also work now
	a, _ = setupAPI(t)
	testManifestInvalidDebugCase(a, manifest, backendPackage)

	// Try setting manifest with UniqueID + other value set, this should fail again
	a, _ = setupAPI(t)
	backendPackage.UniqueID = "something unique"
	manifest.Packages["backend"] = backendPackage

	modRawManifest, err = json.Marshal(manifest)
	require.NoError(err)
	_, err = a.SetManifest(ctx, modRawManifest)
	assert.ErrorContains(err, "manifest specifies both UniqueID *and* SignerID/ProductID/SecurityVersion in package backend")

	// Enable debug mode, should work now
	testManifestInvalidDebugCase(a, manifest, backendPackage)
}

func TestGetManifestSignature_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	api, data := setupAPI(t)

	_, err := api.SetManifest(ctx, []byte(test.ManifestJSON))
	assert.NoError(err)

	sigECDSA, hash, manifest := api.GetManifestSignature(ctx)
	expectedHash := sha256.Sum256([]byte(test.ManifestJSON))
	assert.Equal(expectedHash[:], hash)

	rootPrivK, err := data.GetPrivateKey(constants.SKCoordinatorRootKey)
	require.NoError(err)
	assert.True(ecdsa.VerifyASN1(&rootPrivK.PublicKey, expectedHash[:], sigECDSA))
	assert.Equal([]byte(test.ManifestJSON), manifest)
}

func TestGetSecret_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, data := setupAPI(t)
	ctx := context.Background()

	symmetricSecret := "symmetricKeyShared"
	certSecret := "certShared"
	_, err := c.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	secret1, err := data.GetSecret(symmetricSecret)
	require.NoError(err)
	secret2, err := data.GetSecret(certSecret)
	require.NoError(err)
	admin, err := data.GetUser("admin")
	require.NoError(err)

	// requested secrets should be the same
	reqSecrets, err := c.GetSecrets(ctx, []string{symmetricSecret, certSecret}, admin)
	require.NoError(err)
	assert.True(len(reqSecrets) == 2)
	assert.Equal(secret1, reqSecrets[symmetricSecret])
	assert.Equal(secret2, reqSecrets[certSecret])

	// request should fail if the user lacks permissions
	_, err = c.GetSecrets(ctx, []string{symmetricSecret, "restrictedSecret"}, admin)
	assert.Error(err)

	// requesting a secret should return an empty secret since it was not set
	sec, err := c.GetSecrets(ctx, []string{"symmetricKeyUnset"}, admin)
	require.NoError(err)
	assert.Empty(sec["symmetricKeyUnset"].Public)
	assert.Empty(sec["symmetricKeyUnset"].Private)
}

func TestGetStatus_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := setupAPI(t)
	ctx := context.Background()

	// Server should be ready to accept a manifest after initializing a mock core
	statusCode, status, err := c.GetStatus(ctx)
	assert.NoError(err, "GetStatus failed")
	assert.EqualValues(state.AcceptingManifest, statusCode, "We should be ready to accept a manifest now, but GetStatus tells us we don't.")
	assert.NotEmpty(status, "Status string was empty, but should not.")

	// Set a manifest, state should change
	_, err = c.SetManifest(ctx, []byte(test.ManifestJSON))
	require.NoError(err)
	statusCode, status, err = c.GetStatus(ctx)
	assert.NoError(err, "GetStatus failed")
	assert.EqualValues(state.AcceptingMarbles, statusCode, "We should be ready to accept Marbles now, but GetStatus tells us we don't.")
	assert.NotEmpty(status, "Status string was empty, but should not.")
}

func TestWriteSecrets_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	symmetricSecret := "symmetricKeyUnset"
	certSecret := "certUnset"

	c, data := setupAPI(t)

	_, err := c.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	admin, err := data.GetUser("admin")
	require.NoError(err)

	// there should be no initialized secret yet
	sec, err := data.GetSecret(symmetricSecret)
	require.NoError(err)
	assert.Empty(sec.Public)
	assert.Empty(sec.Private)
	assert.Empty(sec.Cert)
	sec, err = data.GetSecret(certSecret)
	require.NoError(err)
	assert.Empty(sec.Public)
	assert.Empty(sec.Private)

	// set a secret
	err = c.WriteSecrets(ctx, []byte(test.UserSecrets), admin)
	require.NoError(err)
	secret, err := data.GetSecret(symmetricSecret)
	require.NoError(err)
	assert.Equal(16, len(secret.Public))
	secret, err = data.GetSecret(certSecret)
	require.NoError(err)
	assert.Equal("MarbleRun Coordinator - Intermediate CA", secret.Cert.Issuer.CommonName)

	// try to set a secret in plain format
	genericSecret := []byte(`{
		"genericSecret": {
			"Key": "` + base64.StdEncoding.EncodeToString([]byte("MarbleRun Unit Test")) + `"
		}
	}`)
	err = c.WriteSecrets(ctx, genericSecret, admin)
	require.NoError(err)
	secret, err = data.GetSecret("genericSecret")
	require.NoError(err)
	assert.Equal("MarbleRun Unit Test", string(secret.Public))

	// try to set a secret with NULL bytes
	genericSecret = []byte(`{
		"genericSecret": {
			"Key": "` + base64.StdEncoding.EncodeToString([]byte{0x41, 0x41, 0x00, 0x41}) + `"
		}
	}`)
	err = c.WriteSecrets(ctx, genericSecret, admin)
	assert.Error(err)

	// try to set a secret incorrect size
	invalidSecret := []byte(`{
		"symmetricKeyUnset": {
			"Key": "` + base64.StdEncoding.EncodeToString([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) + `"
		}	
	}`)
	err = c.WriteSecrets(ctx, invalidSecret, admin)
	assert.Error(err)
}

func TestUpdateManifest_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, data := setupAPI(t)
	ctx := context.Background()

	// Set manifest
	_, err := c.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	admin, err := data.GetUser("admin")
	require.NoError(err)

	// Get current certificate
	rootCABeforeUpdate, err := data.GetCertificate(constants.SKCoordinatorRootCert)
	assert.NoError(err)
	intermediateCABeforeUpdate, err := data.GetCertificate(constants.SKCoordinatorIntermediateCert)
	assert.NoError(err)
	marbleRootCABeforeUpdate, err := data.GetCertificate(constants.SKMarbleRootCert)
	assert.NoError(err)
	secretsBeforeUpdate, err := data.GetSecretMap()
	assert.NoError(err)

	// Update manifest
	err = c.UpdateManifest(ctx, []byte(test.UpdateManifest), admin)
	require.NoError(err)

	// Get new certificates
	rootCAAfterUpdate, err := data.GetCertificate(constants.SKCoordinatorRootCert)
	assert.NoError(err)
	intermediateCAAfterUpdate, err := data.GetCertificate(constants.SKCoordinatorIntermediateCert)
	assert.NoError(err)
	marbleRootCABeAfterUpdate, err := data.GetCertificate(constants.SKMarbleRootCert)
	assert.NoError(err)
	secretsAfterUpdate, err := data.GetSecretMap()
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
	updateLog, err := c.GetUpdateLog(ctx)
	assert.NoError(err)
	assert.Contains(updateLog, `"package":"frontend"`)
}

func TestUpdateManifestInvalid_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, data := setupAPI(t)
	ctx := context.Background()

	// Good update manifests
	// Set manifest (frontend has SecurityVersion 3)
	_, err := c.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)
	cPackage, err := data.GetPackage("frontend")
	assert.NoError(err)
	assert.EqualValues(3, *cPackage.SecurityVersion)

	// Try to update with unregistered user
	someUser := user.NewUser("invalid", nil)
	err = c.UpdateManifest(ctx, []byte(test.UpdateManifest), someUser)
	assert.Error(err)

	admin, err := data.GetUser("admin")
	assert.NoError(err)

	// Try to update manifest (frontend's SecurityVersion should rise from 3 to 5)
	err = c.UpdateManifest(ctx, []byte(test.UpdateManifest), admin)
	require.NoError(err)
	cUpdatedPackage, err := data.GetPackage("frontend")
	assert.NoError(err)
	assert.EqualValues(5, *cUpdatedPackage.SecurityVersion)

	// Test invalid manifests
	var badUpdateManifest manifest.Manifest
	require.NoError(json.Unmarshal([]byte(test.UpdateManifest), &badUpdateManifest))

	// Add non existing package, should fail
	badUpdateManifest.Packages["nonExisting"] = badUpdateManifest.Packages["frontend"]
	badRawManifest, err := json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(ctx, badRawManifest, admin)
	assert.Error(err)

	delete(badUpdateManifest.Packages, "nonExisting")

	// Test if we cannot enable debug (and thus potentially bypass all these parameters)
	badModPackage := badUpdateManifest.Packages["frontend"]
	badModPackage.Debug = true
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(ctx, badRawManifest, admin)
	assert.Error(err)

	badModPackage.Debug = false

	// Test if no SecurityVersion is defined
	badModPackage.SecurityVersion = nil
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(ctx, badRawManifest, admin)
	assert.Error(err)

	// Test if downgrading fails
	// Alter test update manifest to set the SecurityVersion to '2', which is lower than both, original and update manifest
	badSecurityVersion := uint(2)
	badModPackage.SecurityVersion = &badSecurityVersion
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(ctx, badRawManifest, admin)
	assert.Error(err)

	// Test if downgrading fails
	// Generate a new manifest with SecurityVersion 4, which is higher than the original manifest, but lower than the currently set update manifest (which encorces level 5)
	badSecurityVersion = uint(4)
	badModPackage.SecurityVersion = &badSecurityVersion
	badUpdateManifest.Packages["frontend"] = badModPackage
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(ctx, badRawManifest, admin)
	assert.Error(err)

	// Test if removing a package from a currently existing update manifest fails
	badUpdateManifest.Packages["backend"] = badModPackage
	delete(badUpdateManifest.Packages, "frontend")
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(ctx, badRawManifest, admin)
	assert.Error(err)

	// Test what happens if no packages are defined at all
	badUpdateManifest.Packages = nil
	badRawManifest, err = json.Marshal(badUpdateManifest)
	require.NoError(err)
	err = c.UpdateManifest(ctx, badRawManifest, admin)
	assert.Error(err)
}

func TestUpdateDebugMarble_Legacy(t *testing.T) {
	manifest := []byte(`{
	"Packages": {
		"frontend": {
			"Debug": true
		}
	},
	"Marbles": {
		"frontend": {
			"Package": "frontend"
		}
	},
	"Users": {
		"admin": {
			"Certificate": "-----BEGIN CERTIFICATE-----\nMIIDfzCCAeSgAwIBAgIBKjANBgkqhkiG9w0BAQsFADAAMB4XDTIyMTEzMDEwNTM1\nMVoXDTIzMTEzMDEwNTM1MVowADCCAaUwDQYJKoZIhvcNAQEBBQADggGSADCCAY0C\nggGEAOQy5/JgSgMLipPOXiEd/6WC2dwwdbxaNTeCbw4l7kURezvoAOoD4MR2EivM\nlN1ouD/cZ3supA3QeF1yNXM+m45PYVoZGUH3zdxgsNGrUrI+A9+T9G476uF7l9tL\nrnO/XI6jMHoY8fTudFDWAK4U7/1PJAsOu3fT10ZQwUIwwf6yFrP89HsNGr+c9bfX\nHbFeIcr2mt5+PPRQC9afytOnVlOvmH5xrCTHf/4lN+JtcHAUnn6gv/0+9V6HasQL\nr6y6rWdlty6AnMP3CFG50ydEo2aRDMY/oD+QecaBqeoJPM8nphq2BjfR85PcfY9h\n7mEMhXTCmuJE6yEDR4WWeu2fdcnKgE8FZQhpKgsh2j1AvtCM3uTyPxwmGf9c/64/\n84pWLF/CJkYsHqJmXv62x4uM0Dql3dl7IjhQoMMhfWMCzTPVY6vvMo/mCecmk2w0\nmXNRoKjZ2r1YQoc+adh/bQqbxTFLVbNYAg38Gx74hbVXIifWFoJKGX1F9rGT44ra\n/YWF1IdDSwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBhAAuukuzdycoloQygGj3/DB7\n+KiX9a/6m5PCVGbrafJ/93DBkdYEcs+DrSRj1ThEiZWEfSoreeeEMHtDFhoU/yT7\nl1ns7XxmKPahizxEIM+cMuZslP+LjX33ZslU1alKg3Y9+cK7qZDcMeELWpzri9jd\n1zARyJfC1qmNdjEoihr7zF7o3J/cBL0RB6Zo9ooDA9Q8fCOWPbaU0WDqwZJLk5qe\nASxWEkmj//PYKFq2xc5wMNQrew61PvRwdY/0HRJZTQADdzRC9JmAp9UqlWD80Omk\nlsO+3Jb4dyiHV5wYZuSjq9PjZ6SFeyj/o/Mv0eL+WWtifrSFWqom/hKGoCsLPFqf\noKDdWci7/S07aeAc2rZ/mR2mT5J3zMlvr9wrcAhAYct0hgiru1KYJSBVjh9bHQWj\nvJeG1rolxBAOJ1rT4CGsomf7F8nIyNFw3gWVwFncCBDQgXUp+JENWGbSbjth3+kc\nCX/mAlO2bxdWvVrGszct9zJUZ3LuETZyml5EJw7X1JGTapo=\n-----END CERTIFICATE-----\n",
			"Roles": [
				"updateManager"
			]
		}
	},
	"Roles": {
		"updateManager": {
			"ResourceType": "Packages",
			"ResourceNames": [
				"frontend"
			],
			"Actions": [
				"UpdateSecurityVersion"
			]
		}
	}
}`)
	assert := assert.New(t)
	require := require.New(t)
	ctx := context.Background()

	c, data := setupAPI(t)
	// Set manifest
	_, err := c.SetManifest(ctx, manifest)
	require.NoError(err)

	admin, err := data.GetUser("admin")
	require.NoError(err)
	initialPackage, err := data.GetPackage("frontend")
	require.NoError(err)
	assert.Nil(initialPackage.SecurityVersion)

	// Try to update manifest
	// frontend's security version, which was previously unset, should now be set to 5
	err = c.UpdateManifest(ctx, []byte(test.UpdateManifest), admin)
	require.NoError(err)

	updatedPackage, err := data.GetPackage("frontend")
	require.NoError(err)
	assert.EqualValues(5, *updatedPackage.SecurityVersion)
}

func TestVerifyUser_Legacy(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	c, _ := setupAPI(t)
	ctx := context.Background()

	adminTestCert, otherTestCert := test.MustSetupTestCerts(test.RecoveryPrivateKey)

	// Set a manifest containing an admin certificate
	_, err := c.SetManifest(ctx, []byte(test.ManifestJSONWithRecoveryKey))
	require.NoError(err)

	// Put certificates in slice, as Go's TLS library passes them in an HTTP request
	adminTestCertSlice := []*x509.Certificate{adminTestCert}
	otherTestCertSlice := []*x509.Certificate{otherTestCert}

	// Check if the adminTest certificate is deemed valid (stored in core), and the freshly generated one is deemed false
	user, err := c.VerifyUser(ctx, adminTestCertSlice)
	assert.NoError(err)
	assert.Equal(*user.Certificate(), *adminTestCert)
	_, err = c.VerifyUser(ctx, otherTestCertSlice)
	assert.Error(err)
	_, err = c.VerifyUser(ctx, nil)
	assert.Error(err)
}

func setupAPI(t *testing.T) (*ClientAPI, wrapper.Wrapper) {
	t.Helper()
	require := require.New(t)

	store := stdstore.New(&seal.MockSealer{}, afero.NewMemMapFs(), "")
	log, err := zap.NewDevelopment()
	require.NoError(err)

	wrapper := wrapper.New(store)

	rootCert, rootKey, err := crypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Root", nil, nil, nil)
	require.NoError(err)
	intermediateCert, intermediateKey, err := crypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Intermediate", nil, rootCert, rootKey)
	require.NoError(err)
	marbleCert, _, err := crypto.GenerateCert([]string{"localhost"}, "MarbleRun Unit Test Marble", intermediateKey, nil, nil)
	require.NoError(err)

	require.NoError(wrapper.PutCertificate(constants.SKCoordinatorRootCert, rootCert))
	require.NoError(wrapper.PutCertificate(constants.SKCoordinatorIntermediateCert, intermediateCert))
	require.NoError(wrapper.PutCertificate(constants.SKMarbleRootCert, marbleCert))
	require.NoError(wrapper.PutPrivateKey(constants.SKCoordinatorRootKey, rootKey))
	require.NoError(wrapper.PutPrivateKey(constants.SKCoordinatorIntermediateKey, intermediateKey))

	updateLog, err := updatelog.New()
	require.NoError(err)

	return &ClientAPI{
		core: &fakeCore{
			state:       state.AcceptingManifest,
			getStateMsg: "status message",
		},
		recovery:  recovery.NewSinglePartyRecovery(),
		txHandle:  store,
		log:       log,
		updateLog: updateLog,
	}, wrapper
}
