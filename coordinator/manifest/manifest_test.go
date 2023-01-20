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

	"github.com/edgelesssys/marblerun/coordinator/quote"
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
	err := json.Unmarshal([]byte(test.ManifestJSONWithRecoveryKey), &manifest)
	require.NoError(err)

	zap, err := zap.NewDevelopment()
	require.NoError(err)
	err = manifest.Check(zap)
	assert.NoError(err)

	manifest.Users["anotherUser"] = User{
		Certificate: manifest.Users["admin"].Certificate,
	}
	err = manifest.Check(zap)
	assert.Error(err)
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

func TestIsUpdateManifest(t *testing.T) {
	one := uint(1)
	packages := map[string]quote.PackageProperties{
		"foo": {
			SecurityVersion: &one,
		},
	}

	testCases := map[string]struct {
		manifest Manifest
		wantTrue bool
	}{
		"empty": {
			manifest: Manifest{},
			wantTrue: true,
		},
		"update": {
			manifest: Manifest{
				Packages: packages,
			},
			wantTrue: true,
		},
		"contains marbles": {
			manifest: Manifest{
				Packages: packages,
				Marbles: map[string]Marble{
					"foo": {
						Package: "foo",
					},
				},
			},
		},
		"contains secrets": {
			manifest: Manifest{
				Packages: packages,
				Secrets: map[string]Secret{
					"foo": {
						Type: SecretTypePlain,
					},
				},
			},
		},
		"contains users": {
			manifest: Manifest{
				Packages: packages,
				Users: map[string]User{
					"foo": {
						Certificate: string(test.AdminCert),
					},
				},
			},
		},
		"contains roles": {
			manifest: Manifest{
				Packages: packages,
				Roles: map[string]Role{
					"foo": {
						ResourceType:  "Secrets",
						ResourceNames: []string{"foo"},
						Actions:       []string{"ReadSecret"},
					},
				},
			},
		},
		"contains recovery keys": {
			manifest: Manifest{
				Packages: packages,
				RecoveryKeys: map[string]string{
					"foo": "bar",
				},
			},
		},
		"contains TLS tags": {
			manifest: Manifest{
				Packages: packages,
				TLS: map[string]TLStag{
					"foo": {
						Outgoing: []TLSTagEntry{},
						Incoming: []TLSTagEntry{},
					},
				},
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantTrue, tc.manifest.IsUpdateManifest())
		})
	}
}

func TestTLSTagEqual(t *testing.T) {
	testCases := map[string]struct {
		a, b      TLStag
		wantEqual bool
	}{
		"equal minimal": {
			a:         TLStag{Outgoing: []TLSTagEntry{{Addr: "foo"}}},
			b:         TLStag{Outgoing: []TLSTagEntry{{Addr: "foo"}}},
			wantEqual: true,
		},
		"equal multiple entries": {
			a: TLStag{
				Outgoing: []TLSTagEntry{
					{Addr: "foo", Port: "123"},
					{Addr: "bar", Port: "456"},
					{Addr: "foo", Port: "456"},
				},
			},
			b: TLStag{
				Outgoing: []TLSTagEntry{
					{Addr: "bar", Port: "456"},
					{Addr: "foo", Port: "456"},
					{Addr: "foo", Port: "123"},
				},
			},
			wantEqual: true,
		},
		"equal full": {
			a: TLStag{
				Outgoing: []TLSTagEntry{
					{
						Addr:              "foo",
						Port:              "123",
						Cert:              "cert-1",
						DisableClientAuth: true,
					},
				},
				Incoming: []TLSTagEntry{
					{
						Addr:              "bar",
						Port:              "456",
						Cert:              "cert-2",
						DisableClientAuth: true,
					},
				},
			},
			b: TLStag{
				Outgoing: []TLSTagEntry{
					{
						Addr:              "foo",
						Port:              "123",
						Cert:              "cert-1",
						DisableClientAuth: true,
					},
				},
				Incoming: []TLSTagEntry{
					{
						Addr:              "bar",
						Port:              "456",
						Cert:              "cert-2",
						DisableClientAuth: true,
					},
				},
			},
			wantEqual: true,
		},
		"different outgoing addr": {
			a: TLStag{Outgoing: []TLSTagEntry{{Addr: "foo"}}},
			b: TLStag{Outgoing: []TLSTagEntry{{Addr: "bar"}}},
		},
		"different incoming addr": {
			a: TLStag{Incoming: []TLSTagEntry{{Addr: "foo"}}},
			b: TLStag{Incoming: []TLSTagEntry{{Addr: "bar"}}},
		},
		"different outgoing port": {
			a: TLStag{Outgoing: []TLSTagEntry{{
				Addr: "foo",
				Port: "123",
			}}},
			b: TLStag{Outgoing: []TLSTagEntry{{
				Addr: "foo",
				Port: "456",
			}}},
		},
		"different outgoing cert": {
			a: TLStag{Outgoing: []TLSTagEntry{{
				Addr: "foo",
				Cert: "cert-1",
			}}},
			b: TLStag{Outgoing: []TLSTagEntry{{
				Addr: "foo",
				Cert: "cert-2",
			}}},
		},
		"different outgoing disable client auth": {
			a: TLStag{Outgoing: []TLSTagEntry{{
				Addr:              "foo",
				DisableClientAuth: true,
			}}},
			b: TLStag{Outgoing: []TLSTagEntry{{
				Addr:              "foo",
				DisableClientAuth: false,
			}}},
		},
		"different number of outgoing entries": {
			a: TLStag{Outgoing: []TLSTagEntry{{Addr: "foo"}}},
			b: TLStag{Outgoing: []TLSTagEntry{{Addr: "foo"}, {Addr: "bar"}}},
		},
		"different number of incoming entries": {
			a: TLStag{Incoming: []TLSTagEntry{{Addr: "foo"}}},
			b: TLStag{Incoming: []TLSTagEntry{{Addr: "foo"}, {Addr: "bar"}}},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantEqual, tc.a.Equal(tc.b))
			assert.Equal(t, tc.wantEqual, tc.b.Equal(tc.a))
		})
	}
}

func TestFileEqual(t *testing.T) {
	testCases := map[string]struct {
		a, b      File
		wantEqual bool
	}{
		"equal minimal": {
			a:         File{Data: "foo"},
			b:         File{Data: "foo"},
			wantEqual: true,
		},
		"equal full": {
			a: File{
				Data:        "foo",
				Encoding:    "hex",
				NoTemplates: false,
			},
			b: File{
				Data:        "foo",
				Encoding:    "hex",
				NoTemplates: false,
			},
			wantEqual: true,
		},
		"different data": {
			a: File{Data: "foo"},
			b: File{Data: "bar"},
		},
		"different encoding": {
			a: File{Encoding: "hex"},
			b: File{Encoding: "base64"},
		},
		"different templating policy": {
			a: File{NoTemplates: true},
			b: File{NoTemplates: false},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantEqual, tc.a.Equal(tc.b))
			assert.Equal(t, tc.wantEqual, tc.b.Equal(tc.a))
		})
	}
}

func TestParametersEqual(t *testing.T) {
	testCases := map[string]struct {
		a, b      Parameters
		wantEqual bool
	}{
		"equal minimal": {
			a:         Parameters{Argv: []string{"foo"}},
			b:         Parameters{Argv: []string{"foo"}},
			wantEqual: true,
		},
		"equal full": {
			a: Parameters{
				Argv:  []string{"foo"},
				Env:   map[string]File{"bar": {Data: "baz"}},
				Files: map[string]File{"bar": {Data: "baz"}},
			},
			b: Parameters{
				Argv:  []string{"foo"},
				Env:   map[string]File{"bar": {Data: "baz"}},
				Files: map[string]File{"bar": {Data: "baz"}},
			},
			wantEqual: true,
		},
		"different argv": {
			a: Parameters{Argv: []string{"foo"}},
			b: Parameters{Argv: []string{"bar"}},
		},
		"different argv length": {
			a: Parameters{Argv: []string{"foo"}},
			b: Parameters{Argv: []string{"foo", "bar"}},
		},
		"different argv order": {
			a: Parameters{Argv: []string{"foo", "bar"}},
			b: Parameters{Argv: []string{"bar", "foo"}},
		},
		"different env": {
			a: Parameters{Env: map[string]File{"foo": {Data: "bar"}}},
			b: Parameters{Env: map[string]File{"foo": {Data: "baz"}}},
		},
		"different env length": {
			a: Parameters{Env: map[string]File{"foo": {Data: "bar"}}},
			b: Parameters{Env: map[string]File{"foo": {Data: "bar"}, "bar": {Data: "baz"}}},
		},
		"different files": {
			a: Parameters{Files: map[string]File{"foo": {Data: "bar"}}},
			b: Parameters{Files: map[string]File{"foo": {Data: "baz"}}},
		},
		"different files length": {
			a: Parameters{Files: map[string]File{"foo": {Data: "bar"}, "bar": {Data: "baz"}}},
			b: Parameters{Files: map[string]File{"foo": {Data: "bar"}}},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantEqual, tc.a.Equal(tc.b))
			assert.Equal(t, tc.wantEqual, tc.b.Equal(tc.a))
		})
	}
}

func TestMarbleEqual(t *testing.T) {
	testCases := map[string]struct {
		a, b      Marble
		wantEqual bool
	}{
		"equal minimal": {
			a:         Marble{Package: "foo"},
			b:         Marble{Package: "foo"},
			wantEqual: true,
		},
		"equal full": {
			a: Marble{
				Package:        "foo",
				MaxActivations: 3,
				Parameters: Parameters{
					Argv:  []string{"foo"},
					Env:   map[string]File{"bar": {Data: "baz"}},
					Files: map[string]File{"bar": {Data: "baz"}},
				},
				TLS: []string{"foo", "bar"},
			},
			b: Marble{
				Package:        "foo",
				MaxActivations: 3,
				Parameters: Parameters{
					Argv:  []string{"foo"},
					Env:   map[string]File{"bar": {Data: "baz"}},
					Files: map[string]File{"bar": {Data: "baz"}},
				},
				TLS: []string{"foo", "bar"},
			},
			wantEqual: true,
		},
		"different package": {
			a: Marble{Package: "foo"},
			b: Marble{Package: "bar"},
		},
		"different max activations": {
			a: Marble{MaxActivations: 3},
			b: Marble{MaxActivations: 4},
		},
		"different parameters": {
			a: Marble{Parameters: Parameters{Argv: []string{"foo"}}},
			b: Marble{Parameters: Parameters{Argv: []string{"bar"}}},
		},
		"different tls": {
			a: Marble{TLS: []string{"foo"}},
			b: Marble{TLS: []string{"bar"}},
		},
		"different tls length": {
			a: Marble{TLS: []string{"foo"}},
			b: Marble{TLS: []string{"foo", "bar"}},
		},
		"different tls order": {
			a:         Marble{TLS: []string{"foo", "bar"}},
			b:         Marble{TLS: []string{"bar", "foo"}},
			wantEqual: true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantEqual, tc.a.Equal(tc.b))
			assert.Equal(t, tc.wantEqual, tc.b.Equal(tc.a))
		})
	}
}

func TestSecretEqual(t *testing.T) {
	testCases := map[string]struct {
		a, b                Secret
		wantEqual           bool
		wantEqualDefinition bool
	}{
		"equal symmetric key": {
			a: Secret{
				Type: SecretTypeSymmetricKey,
				Size: 32,
			},
			b: Secret{
				Type: SecretTypeSymmetricKey,
				Size: 32,
			},
			wantEqual:           true,
			wantEqualDefinition: true,
		},
		"symmetric key different size": {
			a: Secret{
				Type: SecretTypeSymmetricKey,
				Size: 32,
			},
			b: Secret{
				Type: SecretTypeSymmetricKey,
				Size: 64,
			},
		},
		"different secret data": {
			a: Secret{
				Type:    SecretTypeSymmetricKey,
				Size:    32,
				Private: bytes.Repeat([]byte{0x00}, 32),
				Public:  bytes.Repeat([]byte{0x00}, 32),
			},
			b: Secret{
				Type:    SecretTypeSymmetricKey,
				Size:    32,
				Private: bytes.Repeat([]byte{0xFF}, 32),
				Public:  bytes.Repeat([]byte{0xFF}, 32),
			},
			wantEqual:           false,
			wantEqualDefinition: true,
		},
		"equal cert": {
			a: Secret{
				Type:     SecretTypeCertRSA,
				Size:     2048,
				ValidFor: 356,
			},
			b: Secret{
				Type:     SecretTypeCertRSA,
				Size:     2048,
				ValidFor: 356,
			},
			wantEqual:           true,
			wantEqualDefinition: true,
		},
		"cert different size": {
			a: Secret{
				Type:     SecretTypeCertRSA,
				Size:     2048,
				ValidFor: 356,
			},
			b: Secret{
				Type:     SecretTypeCertRSA,
				Size:     4096,
				ValidFor: 356,
			},
		},
		"cert different validity": {
			a: Secret{
				Type:     SecretTypeCertRSA,
				Size:     2048,
				ValidFor: 356,
			},
			b: Secret{
				Type:     SecretTypeCertRSA,
				Size:     2048,
				ValidFor: 365,
			},
		},
		"cert secret data does not matter": {
			a: Secret{
				Type:     SecretTypeCertRSA,
				Size:     2048,
				ValidFor: 356,
				Cert:     Certificate{Raw: []byte("foo")},
				Private:  bytes.Repeat([]byte{0x00}, 32),
				Public:   bytes.Repeat([]byte{0x00}, 32),
			},
			b: Secret{
				Type:     SecretTypeCertRSA,
				Size:     2048,
				ValidFor: 356,
				Cert:     Certificate{Raw: []byte("bar")},
				Private:  bytes.Repeat([]byte{0xFF}, 32),
				Public:   bytes.Repeat([]byte{0xFF}, 32),
			},
			wantEqual:           false,
			wantEqualDefinition: true,
		},
		"different type": {
			a: Secret{Type: SecretTypeSymmetricKey},
			b: Secret{Type: SecretTypeCertRSA},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.wantEqual, tc.a.Equal(tc.b))
			assert.Equal(t, tc.wantEqualDefinition, tc.a.EqualDefinition(tc.b))

			assert.Equal(t, tc.wantEqual, tc.b.Equal(tc.a))
			assert.Equal(t, tc.wantEqualDefinition, tc.b.EqualDefinition(tc.a))
		})
	}
}
