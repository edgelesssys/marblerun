# Set a Manifest

The manifest is a JSON document that defines which services span the mesh and how they should be configured.
It further defines what Infrastructure providers are allowed.
You can set a Manifest through Edgeless Mesh's Client REST-API.
The endpoint for all Manifest operations is `/manifest`.

See the following manifest for example (manifest.jso

```json
{
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "SignerID": "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee",
            "ProductID": [1337],
            "SecurityVersion": 1,
			"Debug": false
		},
		"frontend": {
			"UniqueID": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
			"ProductID": [42],
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
	}
}
```

For setting the manifest, we first need to establish trust in the Edgeless Mesh coordinator.
Therefore, we perform a remote attestation step.
Assuming you've deployed our coordinator image from `ghcr.io/edgelesssys/coordinator:latest`:

1. Pull the UniqueID and SignerID values for this image:

    ```bash
    curl -s https://api.github.com/repos/edgelesssys/coordinator/releases/latest \
    | grep "mesh.config" \
    | cut -d '"' -f 4 \
    | wget -qi -
    ```

1. Use the Edgeless Remote Attesation tool to verify the Mesh's quote and get a trusted certificate:

    ```bash
    era -c mesh.config -h <coordinator_addr> -o mesh.crt
    ```

1. Now that we have established trust, we can set the manifest through the Client API:

    ```bash
    curl --silent --cacert mesh.crt -X POST -H  "Content-Type: application/json" --data-binary @manifest.json "https://<coordinator_addr>/manifest"
    ```
