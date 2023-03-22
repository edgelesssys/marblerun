// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetSecrets(t *testing.T) {
	testCases := map[string]struct {
		poster  *stubPoster
		wantErr bool
	}{
		"success": {
			poster:  &stubPoster{},
			wantErr: false,
		},
		"error": {
			poster: &stubPoster{
				err: errors.New("failed"),
			},
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := &cobra.Command{}

			var out bytes.Buffer
			cmd.SetOut(&out)

			err := cliSecretSet(cmd, []byte{0x00}, tc.poster)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Contains(out.String(), "Secret successfully set")
			assert.Equal(rest.SecretEndpoint, tc.poster.requestPath)
			assert.Equal(rest.ContentJSON, tc.poster.header)
		})
	}
}

func TestGetSecrets(t *testing.T) {
	someErr := errors.New("failed")
	testCases := map[string]struct {
		getter    *stubGetter
		file      *file.Handler
		secretIDs []string
		wantErr   bool
	}{
		"success": {
			getter:    &stubGetter{response: []byte(`{"test": "ABCDEF"}`)},
			file:      file.New("unit-test", afero.NewMemMapFs()),
			secretIDs: []string{"test"},
		},
		"get error": {
			getter:    &stubGetter{err: someErr},
			file:      file.New("unit-test", afero.NewMemMapFs()),
			secretIDs: []string{"test"},
			wantErr:   true,
		},
		"write error": {
			getter:    &stubGetter{response: []byte(`{"test": "ABCDEF"}`)},
			file:      file.New("unit-test", afero.NewReadOnlyFs(afero.NewMemMapFs())),
			secretIDs: []string{"test"},
			wantErr:   true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			cmd := &cobra.Command{}

			err := cliSecretGet(cmd, tc.secretIDs, tc.file, tc.getter)
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Contains(tc.getter.requestPath, rest.SecretEndpoint)

			expectedResponse, err := tc.file.Read()
			require.NoError(t, err)
			assert.Equal(expectedResponse, tc.getter.response)
			for _, id := range tc.secretIDs {
				assert.Contains(tc.getter.query, id)
			}
		})
	}
}

func TestSecretFromPEM(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	const testCert = `
-----BEGIN CERTIFICATE-----
MIICpjCCAg+gAwIBAgIUS5FDU/DJnN3hDISm2eAu7hVWqSUwDQYJKoZIhvcNAQEL
BQAwZTELMAkGA1UEBhMCREUxEzARBgNVBAgMClNvbWUtU3RhdGUxGTAXBgNVBAoM
EEVkZ2VsZXNzIFN5c3RlbXMxEjAQBgNVBAsMCVVuaXQgVGVzdDESMBAGA1UEAwwJ
VW5pdCBUZXN0MB4XDTIxMDYyMzA3NTAxMVoXDTIyMDYyMzA3NTAxMVowZTELMAkG
A1UEBhMCREUxEzARBgNVBAgMClNvbWUtU3RhdGUxGTAXBgNVBAoMEEVkZ2VsZXNz
IFN5c3RlbXMxEjAQBgNVBAsMCVVuaXQgVGVzdDESMBAGA1UEAwwJVW5pdCBUZXN0
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDO+ZG7pGx+/poBhr5Zt2lX0+Nh
kcWpYbWdbt69tJXhSWYlZmLeo6FJbeV11bX8zEwVPaDxhYSmlDq2tu9t8o1j8N01
FAoWy4NnDyGEyx1bJGyGGcMN01mVqD+PTbmKeOuVGYchyz8YBub+k5Eft9l6MxuN
kA7SuJGv9fU3lTpQpQIDAQABo1MwUTAdBgNVHQ4EFgQUmD/6vklf6UsdUcZvOB2x
FeymJU0wHwYDVR0jBBgwFoAUmD/6vklf6UsdUcZvOB2xFeymJU0wDwYDVR0TAQH/
BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOBgQCxHFf2dQ+6O/ntEQr6zbHgU4jMidM+
foF2RSiG5icffjDcjpxttJtpIK+iGh3yguGfWaaMVo72DPFPNAVmqHutoEr80chV
yr93zz66XkRPyMhopTeF3Ld1K3qAQ0CqtWck1kblgHCWJBGYgyngawoxSGhUMkSD
i6zr19jszrNxzg==
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIICeAIBADANBgkqhkiG9w0BAQEFAASCAmIwggJeAgEAAoGBAM75kbukbH7+mgGG
vlm3aVfT42GRxalhtZ1u3r20leFJZiVmYt6joUlt5XXVtfzMTBU9oPGFhKaUOra2
723yjWPw3TUUChbLg2cPIYTLHVskbIYZww3TWZWoP49NuYp465UZhyHLPxgG5v6T
kR+32XozG42QDtK4ka/19TeVOlClAgMBAAECgYEAyEX3vUEJ9wx3ixiN4hQ2q9SN
BiFeyVqRuSfKAnjWOquiWngrHVHqRDpBuXa05UvuJvN+Y5YV2HZAJgL3xUTZh+jV
sBgj65evWTUE3daVJBPoTDtBRmZCoEXNvonXbUNFExUwWfDaYOraZCSupP9Yg/0q
m1To7ktkWmS84JuVukECQQDmbVibBLYqIClFsEdNVuVjAq0OHHSsN5FEyD3joQso
JZ5EmCUnp/GvJ+yDgOyKY/gOVK9s9BYKEd7WQQBQ3Vs1AkEA5fHsHtYryPMTl3s7
aycxjEEJyvpDr3y1Pk5tSGdj2YSTvKdkVYP3pJmA0JaCRL/2rqJx3pKuOm1/kOS8
71xdsQJBAJAbLmC0T6CEwIr+tXjesVJ8Z/H9RdI2ZjlX6aykGLAg5pwLcqEcXP+n
vjh3tnbOEmIUACnpdKcTigMAX8wyw0kCQBpYpro9xdSHbWY822kCm527UfjsxdaU
jluuNr1GA13H3/mMoGVf8n7si6Laq+Besk/+EtfyrH3LUAN1AeTXC3ECQQCua5+L
Ra6Yym8Tq+6I6YFqee2NFPKrsKw2xrExhHjx/vv+V0SMXU/zBfZudCbPUcLQoH3q
LuL049+D8bu8Z+Fe
-----END PRIVATE KEY-----`

	secretName := "test-secret"
	secret, err := createSecretFromPEM(secretName, []byte(testCert))
	assert.NoError(err)

	var secretMap map[string]manifest.Secret
	err = json.Unmarshal(secret, &secretMap)
	require.NoError(err)

	_, ok := secretMap[secretName]
	require.True(ok)
	assert.True(len(secretMap[secretName].Cert.Raw) > 0)
	assert.True(len(secretMap[secretName].Private) > 0)
	assert.True(len(secretMap[secretName].Public) == 0)

	// no error here since we stop after finding the first cert-key pair
	_, err = createSecretFromPEM(secretName, []byte(testCert+"\n-----BEGIN MESSAGE-----\ndGVzdA==\n-----END MESSAGE-----"))
	assert.NoError(err)
	// error since the first pem block contains an invalid type
	_, err = createSecretFromPEM(secretName, []byte("-----BEGIN MESSAGE-----\ndGVzdA==\n-----END MESSAGE-----\n"+testCert))
	assert.Error(err)
	_, err = createSecretFromPEM(secretName, []byte("no PEM data here"))
	assert.Error(err)
}
