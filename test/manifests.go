// Copyright (c) Edgeless Systems GmbH.
// Licensed under the MIT License.

package test

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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
				}
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	}
}`

const ManifestJSONWithRecoveryKey string = `{
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
			"Debug": false
		},
		"frontend": {
			"SignerID": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			"ProductID": [44],
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
				}
			}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	},
	"RecoveryKey": "-----BEGIN PUBLIC KEY-----\nMIIBpTANBgkqhkiG9w0BAQEFAAOCAZIAMIIBjQKCAYQAyokHE545y3lU4xsxrqXJ\n58jiaXN8yEdjjuKk0903zMT+FV62UeX17BQhrtdOIf4l4/V/xipqI+osAHBQpRY1\nwM1NCIFFlXUQGgXdtoWiAS7zfFKC+mNlB63Z0Z/50Iw9pl6AFWBQ+16lfmsPMnIu\nLHf4AL3KXVlpgPn6cmRfUoDBx6ITm2QrCDFlVu4j4isgnaZrw6VD0V+G9Mcpgs/0\n0XNmz72eMULfuW+4ULJI9Fx88wiNWWHeSI4vz83ylM5+1QntFROSYWBjgmCnm25j\nKbzV765CVTIU3qq3qkYmclpHfKKt7/TOgVOauvkMCYXyLJkSd1LGLIctWK8tCs1K\nnB237nNg+dZ67Zz9lBYKfNnFoudoc85+vXBRKIfV56FXiXrB32hF1DEj11viMPUr\nroMokLFtDCoAk0Xok4AFQDOgxTw7F8cHskjIYWVCmCqmDUI+FGttyVrc5YLSHAuR\nxQ2oxD0F44JXwxDc/C+OYzOApYl25rmR2nuqioDGpL6/ELRRAgMBAAE=\n-----END PUBLIC KEY-----\n"
}`

const RecoveryKeyPrivateKey string = `-----BEGIN RSA PRIVATE KEY-----
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
CHNE7hk=
-----END RSA PRIVATE KEY-----`

// IntegrationManifestJSON is a test manifest
const IntegrationManifestJSON string = `{
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
			}
		}
		}
	},
	"Clients": {
		"owner": [9,9,9]
	}
}`
