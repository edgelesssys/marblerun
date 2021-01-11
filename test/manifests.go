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
var AdminCert = generateAdminTestCert(RecoveryPrivateKey)

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
			}
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
			}
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
				"SerialNumber": 42,
				"Subject": {
					"SerialNumber": "42",
					"CommonName": "Marblerun Unit Test"
				}
			},
			"ValidFor": 7
		},
		"cert_shared": {
			"Shared": true,
			"Type": "cert-ed25519",
			"Cert": {
				"SerialNumber": 1337,
				"Subject": {
					"SerialNumber": "1337",
					"CommonName": "Marblerun Unit Test"
				}
			},
			"ValidFor": 7
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
	"Clients": {
		"owner": [9,9,9]
	},
	"Admins": {
		"admin": "` + strings.ReplaceAll(string(AdminCert), "\n", "\\n") + `"
	},
	"RecoveryKey": "` + strings.ReplaceAll(string(RecoveryPublicKey), "\n", "\\n") + `"
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
	"RecoveryKey": "` + strings.ReplaceAll(string(RecoveryPublicKey), "\n", "\\n") + `"
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

func generateAdminTestCert(key *rsa.PrivateKey) string {
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

	return string(pemData)
}
