// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetSecrets(t *testing.T) {
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal("/secrets", r.RequestURI)
		assert.Equal(http.MethodPost, r.Method)
		request, err := io.ReadAll(r.Body)
		assert.NoError(err)

		if strings.Contains(string(request), "restrictedSecret") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		if strings.Contains(string(request), `"Type":"invalid"`) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		serverResp := server.GeneralResponse{
			Status: "success",
		}
		assert.NoError(json.NewEncoder(w).Encode(serverResp))
	}))
	defer s.Close()

	err := cliSecretSet(host, []byte(`{"user_secret":{"Type":"plain","Key":"Q0xJIFRlc3QK"}}`), tls.Certificate{}, []*pem.Block{cert})
	assert.NoError(err)

	err = cliSecretSet(host, []byte(`{"restrictedSecret":{"Type":"plain","Key":"Q0xJIFRlc3QK"}}`), tls.Certificate{}, []*pem.Block{cert})
	assert.Error(err)

	err = cliSecretSet(host, []byte(`{"user_secret":{"Type":"invalid","Key":"Q0xJIFRlc3QK"}}`), tls.Certificate{}, []*pem.Block{cert})
	assert.Error(err)
}

func TestGetSecrets(t *testing.T) {
	assert := assert.New(t)
	s, host, cert := newTestServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(http.MethodGet, r.Method)
		if r.RequestURI == "/secrets?s=plain_secret&s=certShared&s=secretOne" {
			serverResp := server.GeneralResponse{
				Status: "success",
				Data: map[string]interface{}{
					"plain_secret": map[string]interface{}{
						"Type":        manifest.SecretTypePlain,
						"Size":        0,
						"Shared":      false,
						"UserDefined": true,
						"Cert":        nil,
						"ValidFor":    0,
						"Private":     "base64-data",
						"Public":      "base64-data",
					},
					"secretOne": map[string]interface{}{
						"Type":        manifest.SecretTypeSymmetricKey,
						"Size":        128,
						"Shared":      true,
						"UserDefined": false,
						"Cert":        nil,
						"ValidFor":    0,
						"Private":     "base64-priv-data",
						"Public":      "base64-priv-data",
					},
					"certShared": map[string]interface{}{
						"Type":        manifest.SecretTypeCertRSA,
						"Size":        2048,
						"Shared":      true,
						"UserDefined": false,
						"Cert":        "base64-cert-data",
						"ValidFor":    14,
						"Private":     "base64-priv-data",
						"Public":      "base64-pub-data",
					},
				},
			}
			assert.NoError(json.NewEncoder(w).Encode(serverResp))
			return
		}
		if r.RequestURI == "/secrets?s=restrictedSecret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer s.Close()
	options := &secretGetOptions{
		host: host,
		secretIDs: []string{
			"plain_secret",
			"certShared",
			"secretOne",
		},
		output: "",
		clCert: tls.Certificate{},
		caCert: []*pem.Block{cert},
	}

	var out bytes.Buffer

	err := cliSecretGet(&out, options)
	assert.NoError(err)

	options.secretIDs = []string{"restrictedSecret"}
	err = cliSecretGet(&out, options)
	assert.Error(err)

	options.secretIDs = []string{"this should cause an error"}
	err = cliSecretGet(&out, options)
	assert.Error(err)
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
	secret, err := loadSecretFromPEM(secretName, []byte(testCert))
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
	_, err = loadSecretFromPEM(secretName, []byte(testCert+"\n-----BEGIN MESSAGE-----\ndGVzdA==\n-----END MESSAGE-----"))
	assert.NoError(err)
	// error since the first pem block contains an invalid type
	_, err = loadSecretFromPEM(secretName, []byte("-----BEGIN MESSAGE-----\ndGVzdA==\n-----END MESSAGE-----\n"+testCert))
	assert.Error(err)
	_, err = loadSecretFromPEM(secretName, []byte("no PEM data here"))
	assert.Error(err)
}
