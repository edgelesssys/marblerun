// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"strings"
	"time"
)

var RecoveryPublicKey, RecoveryPrivateKey = generateTestRecoveryKey()

// AdminCert is an automatically generated test certificate used for unit tests for API features needing additional authentication.
var AdminCert = mustGenerateAdminTestCert(RecoveryPrivateKey)

// ManifestJSON is a test manifest.
const ManifestJSON string = `{
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"Debug": false
		},
		"frontend": {
			"SignerID": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			"ProductID": 44,
			"SecurityVersion": 3,
			"Debug": true
		}
	},
	"Infrastructures": {
		"Azure": {
			"QESVN": 2,
			"PCESVN": 3,
			"CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"RootCA": [3,3,3]
		},
		"Alibaba": {
			"QESVN": 2,
			"PCESVN": 4,
			"CPUSVN": [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
			"RootCA": [4,4,4]
		}
	},
	"Marbles": {
		"backendFirst": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Files": {
					"/tmp/defg.txt": "foo",
					"/tmp/jkl.mno": "bar",
					"/tmp/base64.txt": {
						"Data": "TWFyYmxlUnVuIGJhc2U2NA==",
						"Encoding": "base64",
						"NoTemplates": true
					}
				},
				"Env": {
					"IS_FIRST": "true",
					"TEST_SECRET_SYMMETRIC_KEY": {
						"Data": "{{ hex .Secrets.symmetricKeyShared }}",
						"Encoding": "string"
					},
					"TEST_SECRET_CERT": "{{ pem .Secrets.certShared.Cert }}",
					"TEST_SECRET_PRIVATE_CERT": "{{ pem .Secrets.certPrivate.Cert }}"
				},
				"Argv": [
					"--first",
					"serve"
				]
			},
			"TLS": [
				"web"
			]
		},
		"backendOther": {
			"Package": "backend",
			"Parameters": {
				"Env": {
					"TEST_SECRET_CERT": "{{ pem .Secrets.certShared.Cert }}",
					"TEST_SECRET_PRIVATE_CERT": "{{ pem .Secrets.certPrivate.Cert }}"
				},
				"Argv": [
					"serve"
				]
			},
			"TLS": [
				"web",
				"anotherWeb"
			]
		},
		"frontend": {
			"Package": "frontend"
		}
	},
	"Secrets": {
		"symmetricKeyShared": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetricKeyPrivate": {
			"Size": 256,
			"Type": "symmetric-key"
		},
		"certPrivate": {
			"Size": 2048,
			"Type": "cert-rsa",
			"Cert": {
				"Subject": {
					"CommonName": "MarbleRun Unit Test Private"
				}
			},
			"ValidFor": 7
		},
		"certShared": {
			"Shared": true,
			"Type": "cert-ed25519",
			"Cert": {
				"Subject": {
					"CommonName": "MarbleRun Unit Test Shared"
				}
			},
			"ValidFor": 7
		}
	},
	"TLS": {
		"web": {
			"Outgoing": [
				{
					"Port": "8080",
					"Addr": "localhost"
				},
				{
					"Port": "4242",
					"Addr": "service.namespace"
				}
			],
			"Incoming": [
				{
					"Port": "8080"
				}
			]
		},
		"anotherWeb": {
			"Outgoing": [
				{
					"Port": "40000",
					"Addr": "example.com"
				}
			],
			"Incoming": [
				{
					"Port": "8080",
					"Cert": "certShared",
					"DisableClientAuth": true
				}
			]
		}
	}
}`

// ManifestJSONWithRecoveryKey is a test manifest with a dynamically generated RSA key.
var ManifestJSONWithRecoveryKey string = `{
	"Packages": {
		"frontend": {
			"SignerID": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			"ProductID": 44,
			"SecurityVersion": 3,
			"Debug": true
		}
	},
	"Infrastructures": {
		"Azure": {
			"QESVN": 2,
			"PCESVN": 3,
			"CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"RootCA": [3,3,3]
		}
	},
	"Marbles": {
		"frontend": {
			"Package": "frontend"
		},
		"envMarble": {
			"Package": "frontend",
			"Parameters": {
				"Env": {
					"ENV_SECRET": "{{ string .Secrets.genericSecret }}"
				}
			}
		}
	},
	"Secrets": {
		"restrictedSecret": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetricKeyShared": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetricKeyPrivate": {
			"Size": 256,
			"Type": "symmetric-key"
		},
		"certPrivate": {
			"Size": 2048,
			"Type": "cert-rsa",
			"Cert": {
				"Subject": {
					"CommonName": "MarbleRun Unit Test Private"
				}
			},
			"ValidFor": 7
		},
		"certShared": {
			"Shared": true,
			"Type": "cert-ed25519",
			"Cert": {
				"Subject": {
					"CommonName": "MarbleRun Unit Test Shared"
				}
			},
			"ValidFor": 7
		},
		"symmetricKeyUnset": {
			"Type": "symmetric-key",
			"Size": 128,
			"UserDefined": true
		},
		"certUnset": {
			"Type": "cert-ed25519",
			"UserDefined": true
		},
		"genericSecret": {
			"UserDefined": true,
			"Type": "plain"
		}
	},
	"Users": {
		"admin": {
			"Certificate": "` + pemToJSONString(AdminCert) + `",
			"Roles": [
				"secretManager",
				"readOnly",
				"updateManager"
			]
		}
	},
	"RecoveryKeys": {
		"testRecKey1": "` + pemToJSONString(RecoveryPublicKey) + `"
	},
	"Roles": {
		"secretManager": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetricKeyUnset",
				"certUnset",
				"genericSecret"
			],
			"Actions": [
				"ReadSecret",
				"WriteSecret"
			]
		},
		"readOnly": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetricKeyShared",
				"certShared"
			],
			"Actions": [
				"ReadSecret"
			]
		},
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
}`

// IntegrationManifestJSON is a test manifest.
var IntegrationManifestJSON string = `{
	"Packages": {
		"backend": {
			"Debug": true,
			"SecurityVersion": 1,
			"ProductID": 3
		},
		"frontend": {
			"Debug": true,
			"SecurityVersion": 2,
			"ProductID": 3
		}
	},
	"Infrastructures": {
		"Azure": {
			"QESVN": 2,
			"PCESVN": 3,
			"CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"RootCA": [3,3,3]
		}
	},
	"Marbles": {
		"testMarbleServer": {
			"Package": "backend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar",
					"/tmp/coordinator_test/secret.raw": "{{ raw .Secrets.symmetricKeyShared }}{{ raw .MarbleRun.MarbleCert.Private }}"
				},
				"Argv": [
					"./marble",
					"serve"
				],
				"Env": {
					"IS_FIRST": "true"
				}
			}
		},
		"testMarbleClient": {
			"Package": "backend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar"
				},
				"Env": {
					"IS_FIRST": "true"
				}
			}
		},
		"testMarbleUnset": {
			"Package": "backend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar",
					"/tmp/coordinator_test/pqr.txt": "user-defined secret: {{ raw .Secrets.symmetricKeyUnset }} {{ pem .Secrets.certUnset.Private }}"
				},
				"Env": {
					"IS_FIRST": "true"
				}
			}
		},
		"badMarble": {
			"Package": "frontend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar"
				}
			}
		}
	},
	"Secrets" :{
		"symmetricKeyShared": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetricKeyUnset": {
			"Shared": true,
			"Type": "symmetric-key",
			"Size": 128,
			"UserDefined": true
		},
		"certUnset": {
			"Shared": true,
			"Type": "cert-ed25519",
			"UserDefined": true
		}
	},
	"Users": {
		"admin": {
			"Certificate": "` + pemToJSONString(AdminCert) + `",
			"Roles": [
				"writeRole",
				"readRole",
				"updateRole"
			]
		}
	},
	"RecoveryKeys": {
		"testRecKey1": "` + pemToJSONString(RecoveryPublicKey) + `"
	},
	"Roles": {
		"writeRole": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetricKeyUnset",
				"certUnset"
			],
			"Actions": [
				"WriteSecret"
			]
		},
		"readRole": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetricKeyShared"
			],
			"Actions": [
				"ReadSecret"
			]
		},
		"updateRole": {
			"ResourceType": "Packages",
			"ResourceNames": [
				"frontend",
				"backend"
			],
			"Actions": [
				"UpdateSecurityVersion"
			]
		}
	}
}`

// ManifestJSONMissingParameters is a test manifest.
var ManifestJSONMissingParameters string = `{
	"Packages": {
		"frontend": {
			"SignerID": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			"ProductID": 44,
			"SecurityVersion": 3,
			"Debug": true
		}
	},
	"Infrastructures": {
		"Azure": {
			"QESVN": 2,
			"PCESVN": 3,
			"CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
			"RootCA": [3,3,3]
		}
	},
	"Marbles": {
		"frontend": {
			"Package": "frontend"
		}
	}
}`

func generateTestRecoveryKey() (publicKeyPem []byte, privateKey *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 3096)
	if err != nil {
		panic(err)
	}

	pkixPublicKey, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pkixPublicKey,
	}

	return pem.EncodeToMemory(publicKeyBlock), key
}

// UpdateManifest is a test update manifest.
const UpdateManifest = `{
	"Packages": {
		"frontend": {
			"SecurityVersion": 5
		}
	}
}`

// UserSecrets is a test JSON string to update secrets.
const UserSecrets = `{
	"symmetricKeyUnset": {
		"Key": "AAECAwQFBgcICQoLDA0ODw=="
	},
	"certUnset": {
		"Cert": "MIIBrzCCAVWgAwIBAgIQT7thUhyIwo2TVzlWFWOl6TAKBggqhkjOPQQDAjAyMTAwLgYDVQQDEydNYXJibGVSdW4gQ29vcmRpbmF0b3IgLSBJbnRlcm1lZGlhdGUgQ0EwHhcNMjEwODEyMDg0NjAzWhcNMjEwODE5MDg0NjAzWjAeMRwwGgYDVQQDExNNYXJibGVSdW4gVW5pdCBUZXN0MCowBQYDK2VwAyEAoZp0yve1E/F9KnIVzddz1dj4Rr0ufH9bjEVBpJr5fEejgY8wgYwwDgYDVR0PAQH/BAQDAgKEMB0GA1UdJQQWMBQGCCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFE0N9WzWoWzDR315bGivlMymiBBgMCwGA1UdEQQlMCOCCWxvY2FsaG9zdIcEfwAAAYcQAAAAAAAAAAAAAAAAAAAAATAKBggqhkjOPQQDAgNIADBFAiEAi0I1HVqVb8l9C8rrx2TcvEhJt9Ex8Ih1pFhdCVsc5CQCIETgi3eHKZpG+5q9AS59PxsV3zaC3mAJmsqrLbJsOo31",
		"Private": "MC4CAQAwBQYDK2VwBCIEIMQy0nTlMFQk+NfVk0gnCYxADCw+C7tEo0Xqj7vX20dg"
	}
}`

func mustGenerateAdminTestCert(key *rsa.PrivateKey) []byte {
	// Create some demo certificate
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

	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: testCertRaw})
	return pemData
}

func pemToJSONString(pem []byte) string {
	return strings.ReplaceAll(string(pem), "\n", "\\n")
}

// MustSetupTestCerts can be used by other unit tests to test authentication features, in which one certificate matches the generated admin certificate, and the other is just a randomly generated one.
func MustSetupTestCerts(key *rsa.PrivateKey) (*x509.Certificate, *x509.Certificate) {
	// Create some demo certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1337),
		IsCA:         false,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour * 24 * 365),
	}

	otherTestCertRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	otherTestCert, err := x509.ParseCertificate(otherTestCertRaw)
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(AdminCert)
	adminTestCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	return adminTestCert, otherTestCert
}
