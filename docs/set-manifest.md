# Setting a Manifest

The Manifest is a JSON document that defines which services span the mesh and how they should be configured.
It further defines what Infrastructure providers are allowed.
You can set a Manifest through Marblerun's Client REST-API.
The endpoint for all Manifest operations is `/manifest`.

See the following Manifest for example (`manifest.json`).

```json
{
    "Packages": {
        "backend": {
            "UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "ProductID": 43,
            "SecurityVersion": 1,
            "Debug": false
        },
        "frontend": {
            "SignerID": "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee",
            "ProductID": 42,
            "SecurityVersion": 3,
            "Debug": true
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

For setting the Manifest, we first need to establish trust in the Coordinator.
Therefore, we perform a remote attestation step.
Assuming you've deployed our Coordinator image from `ghcr.io/edgelesssys/coordinator`:

1. Pull the UniqueID and SignerID values for this image:

    ```bash
    wget https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json
    ```

2. Use the Edgeless Remote Attestation tool to verify the Mesh's quote and get a trusted certificate:

    ```bash
    era -c coordinator-era.json -h $MARBLERUN -o marblerun.crt
    ```

3. Now that we have established trust, we can set the Manifest through the Client API:

    ```bash
    curl --cacert marblerun.crt --data-binary @manifest.json "https://$MARBLERUN/manifest"
    ```
