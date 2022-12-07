// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package manifest

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/user"
	"github.com/edgelesssys/marblerun/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestFile(t *testing.T) {
	dataJSON := []byte(`
{
	"string": "helloworld",
	"stringStruct": {
		"Encoding": "string",
		"NoTemplates": false,
		"Data": "foo"
	},
	"base64": {
		"Encoding": "base64",
		"NoTemplates": true,
		"Data": "YmFy"
	},
	"base64Value": {
		"Encoding": "string",
		"Data": "YmFy"
	},
	"hex": {
		"Encoding": "hex",
		"Data": "4d6172626c6552756e"
	},
	"withoutTemplates": {
		"Encoding": "string",
		"NoTemplates": true,
		"Data": "{{ string .Secrets.symmetricKeyShared }}"
	}
}`)
	assert := assert.New(t)
	require := require.New(t)

	testFiles := make(map[string]File)
	err := json.Unmarshal(dataJSON, &testFiles)
	require.NoError(err)
	assert.Equal("helloworld", testFiles["string"].Data)
	assert.Equal("string", testFiles["string"].Encoding)
	assert.Equal("foo", testFiles["stringStruct"].Data)
	assert.Equal("bar", testFiles["base64"].Data)
	assert.Equal("YmFy", testFiles["base64Value"].Data)
	assert.Equal("MarbleRun", testFiles["hex"].Data)
	assert.Equal("{{ string .Secrets.symmetricKeyShared }}", testFiles["withoutTemplates"].Data)

	_, err = json.Marshal(testFiles)
	assert.NoError(err)
}

func TestTemplateDryRun(t *testing.T) {
	testCases := map[string]struct {
		manifest []byte
		secrets  map[string]Secret
		wantErr  bool
	}{
		"valid": {
			manifest: []byte(`{
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
							"/tmp/abc.txt": "{{ raw .Secrets.bar }}",
							"/tmp/defg.txt": "{{ hex .Secrets.foo }}"
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
				"bar": {
					"Size": 128,
					"Shared": true,
					"Type": "symmetric-key"
				}
			}
			}`),
		},
		"missingSecret": {
			manifest: []byte(`{
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
			}`),
			wantErr: true,
		},
		"wrongType": {
			manifest: []byte(`{
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
			}`),
			wantErr: true,
		},
		"rawInEnv": {
			manifest: []byte(`{
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
			}`),
			wantErr: true,
		},
		"nullByte": {
			manifest: []byte(`{
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
			}`),
			wantErr: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			var manifest Manifest
			require.NoError(json.Unmarshal(tc.manifest, &manifest))

			// generate secrets
			for secretName, secret := range manifest.Secrets {
				switch secret.Type {
				case SecretTypeSymmetricKey:
					secret.Private = bytes.Repeat([]byte{0x00}, 32)
					secret.Public = bytes.Repeat([]byte{0x00}, 32)
					manifest.Secrets[secretName] = secret
				}
			}

			err := manifest.TemplateDryRun(manifest.Secrets)
			if tc.wantErr {
				assert.Error(err)
				fmt.Println(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}

func TestManifestCheck(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	var manifest Manifest
	err := json.Unmarshal([]byte(test.ManifestJSON), &manifest)
	require.NoError(err)

	zap, err := zap.NewDevelopment()
	require.NoError(err)
	err = manifest.Check(zap)
	assert.NoError(err)
}

func TestCertificate(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	block, _ := pem.Decode(test.AdminCert)
	cert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(err)

	certJSON, err := json.Marshal(Certificate(*cert))
	assert.NoError(err)

	var cert2 Certificate
	err = json.Unmarshal(certJSON, &cert2)
	assert.NoError(err)
	assert.Equal(cert.Raw, cert2.Raw)
}

func TestGenerateUsers(t *testing.T) {
	assert := assert.New(t)

	mnf := Manifest{
		Users: map[string]User{
			"Alice": {
				Certificate: string(test.AdminCert),
				Roles:       []string{"writeRole", "readRole"},
			},
			"Bob": {
				Certificate: string(test.AdminCert),
				Roles:       []string{"writeRole", "updateRole"},
			},
		},
		Roles: map[string]Role{
			"writeRole": {
				ResourceType:  "Secrets",
				ResourceNames: []string{"secretOne"},
				Actions:       []string{"WriteSecret"},
			},
			"readRole": {
				ResourceType:  "Secrets",
				ResourceNames: []string{"secretOne", "secretTwo"},
				Actions:       []string{"readsecret"},
			},
			"updateRole": {
				ResourceType:  "Packages",
				ResourceNames: []string{"frontend", "backend"},
				Actions:       []string{"UpdateSecurityVersion"},
			},
		},
	}
	newUsers, err := mnf.GenerateUsers()
	assert.NoError(err)
	assert.Equal(len(mnf.Users), len(newUsers))
	for _, newUser := range newUsers {
		switch newUser.Name() {
		case "Alice":
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionWriteSecret, []string{"secretOne"})))
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionReadSecret, []string{"secretOne", "secretTwo"})))
			assert.False(newUser.IsGranted(user.NewPermission(user.PermissionUpdatePackage, []string{"frontend", "backend"})))
		case "Bob":
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionWriteSecret, []string{"secretOne"})))
			assert.False(newUser.IsGranted(user.NewPermission(user.PermissionReadSecret, []string{"secretOne", "secretTwo"})))
			assert.True(newUser.IsGranted(user.NewPermission(user.PermissionUpdatePackage, []string{"frontend", "backend"})))
		}
	}

	// try to generate new users with missing certificate, this should always error
	mnf.Users = map[string]User{
		"Alice": {
			Roles: []string{"writeRole"},
		},
		"Bob": {
			Certificate: string(test.AdminCert),
			Roles:       []string{"updateRole"},
		},
	}
	_, err = mnf.GenerateUsers()
	assert.Error(err)
}
