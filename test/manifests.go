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
	"strings"
)

var RecoveryPublicKey, RecoveryPrivateKey = generateTestRecoveryKey()

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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}",
					"TEST_SECRET_RAW": "{{ raw .Secrets.testsecret_raw }}"
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
				}
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	},
	"Secrets": {
		"testsecret_raw": {
			"size": 128,
			"type": "raw"
		},
		"testsecret_cert": {
			"size": 2048,
			"type": "cert-rsa",
			"Cert": {
				"SerialNumber": 42,
				"Subject": {
					"SerialNumber": "42",
					"CommonName": "Marblerun Unit Test"
				},
			"validfor": 7
			}
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
				}
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
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
