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

// ManifestJSON is a test manifest
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
		"backend_first": {
			"Package": "backend",
			"MaxActivations": 1,
			"Parameters": {
				"Files": {
					"/tmp/defg.txt": "foo",
					"/tmp/jkl.mno": "bar"
				},
				"Env": {
					"IS_FIRST": "true",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"TEST_SECRET_SYMMETRIC_KEY": "{{ raw .Secrets.symmetric_key_shared }}",
					"TEST_SECRET_CERT": "{{ pem .Secrets.cert_shared.Cert }}",
					"TEST_SECRET_PRIVATE_CERT": "{{ pem .Secrets.cert_private.Cert }}"
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
		"backend_other": {
			"Package": "backend",
			"Parameters": {
				"Env": {
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"TEST_SECRET_CERT": "{{ pem .Secrets.cert_shared.Cert }}",
					"TEST_SECRET_PRIVATE_CERT": "{{ pem .Secrets.cert_private.Cert }}"
				},
				"Argv": [
					"serve"
				]
			},
			"TLS": [
				"web", "anotherWeb"
			]
		},
		"frontend": {
			"Package": "frontend",
			"Parameters": {
				"Env": {
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}"
				}
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	},
	"Secrets": {
		"symmetric_key_shared": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetric_key_private": {
			"Size": 256,
			"Type": "symmetric-key"
		},
		"cert_private": {
			"Size": 2048,
			"Type": "cert-rsa",
			"Cert": {
				"Subject": {
					"CommonName": "Marblerun Unit Test Private"
				}
			},
			"ValidFor": 7
		},
		"cert_shared": {
			"Shared": true,
			"Type": "cert-ed25519",
			"Cert": {
				"Subject": {
					"CommonName": "Marblerun Unit Test Shared"
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
					"Cert": "cert_shared",
					"DisableClientAuth": true
				}
			]
		}
	}
}`

// ManifestJSONWithRecoveryKey is a test manifest with a dynamically generated RSA key
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
			"Package": "frontend",
			"Parameters": {
				"Env": {
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}"
				}
			}
		}
	},
	"Secrets": {
		"restricted_secret": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetric_key_shared": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetric_key_private": {
			"Size": 256,
			"Type": "symmetric-key"
		},
		"cert_private": {
			"Size": 2048,
			"Type": "cert-rsa",
			"Cert": {
				"Subject": {
					"CommonName": "Marblerun Unit Test Private"
				}
			},
			"ValidFor": 7
		},
		"cert_shared": {
			"Shared": true,
			"Type": "cert-ed25519",
			"Cert": {
				"Subject": {
					"CommonName": "Marblerun Unit Test Shared"
				}
			},
			"ValidFor": 7
		},
		"symmetric_key_unset": {
			"Type": "symmetric-key",
			"Size": 128,
			"UserDefined": true
		},
		"cert_unset": {
			"Type": "cert-ed25519",
			"UserDefined": true
		},
		"generic_secret": {
			"UserDefined": true,
			"Type": "plain"
		}
	},
	"Clients": {
		"owner": [9,9,9]
	},
	"Users": {
		"admin": {
			"Certificate": "` + pemToJSONString(AdminCert) + `",
			"Roles": [
				"secret_manager",
				"read_only",
				"update_manager"
			]
		}
	},
	"RecoveryKeys": {
		"testRecKey1": "` + pemToJSONString(RecoveryPublicKey) + `"
	},
	"Roles": {
		"secret_manager": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetric_key_unset",
				"cert_unset",
				"generic_secret"
			],
			"Actions": [
				"ReadSecret",
				"WriteSecret"
			]
		},
		"read_only": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetric_key_shared",
				"cert_shared"
			],
			"Actions": [
				"ReadSecret"
			]
		},
		"update_manager": {
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

// IntegrationManifestJSON is a test manifest
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
		"test_marble_server": {
			"Package": "backend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar"
				},
				"Argv": [
					"./marble",
					"serve"
				],
				"Env": {
					"IS_FIRST": "true",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}"
				}
			}
		},
		"test_marble_client": {
			"Package": "backend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar"
				},
				"Env": {
					"IS_FIRST": "true",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}"
				}
			}
		},
		"test_marble_unset": {
			"Package": "backend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar",
					"/tmp/coordinator_test/pqr.txt": "user-defined secret: {{ hex .Secrets.symmetric_key_unset }} {{ pem .Secrets.cert_unset.Private }}"
				},
				"Env": {
					"IS_FIRST": "true",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}"
				}
			}
		},
		"bad_marble": {
			"Package": "frontend",
			"Parameters": {
				"Files": {
					"/tmp/coordinator_test/defg.txt": "foo",
					"/tmp/coordinator_test/jkl.mno": "bar"
				},
				"Env": {
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}"
				}
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	},
	"Secrets" :{
		"symmetric_key_shared": {
			"Size": 128,
			"Shared": true,
			"Type": "symmetric-key"
		},
		"symmetric_key_unset": {
			"Shared": true,
			"Type": "symmetric-key",
			"Size": 128,
			"UserDefined": true
		},
		"cert_unset": {
			"Shared": true,
			"Type": "cert-ed25519",
			"UserDefined": true
		}
	},
	"Users": {
		"admin": {
			"Certificate": "` + pemToJSONString(AdminCert) + `",
			"Roles": [
				"write_role",
				"read_role",
				"update_role"
			]
		}
	},
	"RecoveryKeys": {
		"testRecKey1": "` + pemToJSONString(RecoveryPublicKey) + `"
	},
	"Roles": {
		"write_role": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetric_key_unset",
				"cert_unset"
			],
			"Actions": [
				"WriteSecret"
			]
		},
		"read_role": {
			"ResourceType": "Secrets",
			"ResourceNames": [
				"symmetric_key_shared"
			],
			"Actions": [
				"ReadSecret"
			]
		},
		"update_role": {
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

// ManifestJSONMissingParameters is a test manifest
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

// UpdateManifest is a test update manifest
const UpdateManifest = `{
	"Packages": {
		"frontend": {
			"SecurityVersion": 5
		}
	}
}`

// UserSecrets is a test JSON string to update secrets
const UserSecrets = `{
	"symmetric_key_unset": {
		"Key": "AAECAwQFBgcICQoLDA0ODw=="
	},
	"cert_unset": { 
		"Cert": "MIIBjDCCATOgAwIBAgICBTkwCgYIKoZIzj0EAwIwMjEwMC4GA1UEAxMnTWFyYmxlcnVuIENvb3JkaW5hdG9yIC0gSW50ZXJtZWRpYXRlIENBMB4XDTIxMDYxNTA4NTY0M1oXDTIxMDYyMjA4NTY0M1owLTEcMBoGA1UEAxMTTWFyYmxlcnVuIFVuaXQgVGVzdDENMAsGA1UEBRMEMTMzNzAqMAUGAytlcAMhAEPOc066G5XmvLizOKTENSR+U9lv3geZ0/a2+XkhJRvDo20wazAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwLAYDVR0RBCUwI4IJbG9jYWxob3N0hwR/AAABhxAAAAAAAAAAAAAAAAAAAAABMAoGCCqGSM49BAMCA0cAMEQCIGOlRcynaPaj/flSr2ZEvmTmhuvtmTb4QkwPFtxFz3EJAiB77ijxAcJNxPKcKmgMB+c8NORC+6N/St2iP/oX/vqQvg==",
		"Private": "MC4CAQAwBQYDK2VwBCIEIPlmAOOhAStk8ytxzvekPr8zLaQa9+lxnHK+CizDrMds"
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

// MustSetupTestCerts can be used by other unit tests to test authentication features, in which one certificate matches the generated admin certificate, and the other is just a randomly generated one
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
