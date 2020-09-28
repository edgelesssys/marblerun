package test

const ManifestJSON string = `{
	"Packages": {
		"backend": {
			"UniqueID": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31],
			"Debug": false
		},
		"frontend": {
			"SignerID": [31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
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
	}
}`

// TODO: Use correct values here
const IntegrationManifestJSON string = `{
	"Packages": {
		"backend": {
			"Debug": true,
			"SecurityVersion": 1,
			"ProductID": [3]
		},
		"frontend": {
			"Debug": true,
			"SecurityVersion": 2,
			"ProductID": [3]
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
					"/tmp/defg.txt": "foo",
					"/tmp/jkl.mno": "bar"
				},
				"Argv": [
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
					"/tmp/defg.txt": "foo",
					"/tmp/jkl.mno": "bar"
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
					"/tmp/defg.txt": "foo",
					"/tmp/jkl.mno": "bar"
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
