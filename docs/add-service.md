# Add a service

Adding a service to your application requires two steps:

1. Building your service together with Marblerun to inject our *Marble* data plane.
2. Adding the service to the manifest so it will be recognized and managed by the *Coordinator* control plane.

## Building your service with Marblerun

We distinguish two cases when building your confidential application with Marblerun:

1. Your service is written in Go
    * You need to build your project together with our *Marble* code
    * We have an example on how to do this [here](https://github.com/edgelesssys/marblerun/blob/master/samples/helloworld/README.md)

1. Your service is written in any other language that can be compiled to binary code (e.g. C++)
    * You need to link your code against our *Marble* library
    * We have an example on how to do this [here](https://github.com/edgelesssys/marblerun/blob/master/samples/helloc%2B%2B/README.md)

## Adding your service to the Manifest

The manifest contains a section with the information used to authenticate each service in the mesh:

```json
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "SignerID": "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee",
            "ProductID": 1337,
            "SecurityVersion": 1,
			"Debug": false
		},
    }
```

These values correspond directly to values provided in a remote attestation quote from Intel SGX.
Marblerun provides a tool to extract these values from a signed enclave.
You can find this tool in [tools/create_config.py](https://github.com/edgelesssys/marblerun/blob/master/tools/create_config.py):

```bash
tools/create_config.py -e enclave.signed
```

You'll see something like this:

```json
{
    "SecurityVersion": 1,
    "ProductID": 3
    "UniqueID": "6b2822ac2585040d4b9397675d54977a71ef292ab5b3c0a6acceca26074ae585",
    "SignerID": "5826218dbe96de0d7b3b1ccf70ece51457e71e886a3d4c1f18b27576d22cdc74"
}
```

You can add this directly to your `manifest.json` file like so:

```json
	"Packages": {
		"backend": {
			"UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "SignerID": "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee",
            "ProductID": 1337,
            "SecurityVersion": 1,
			"Debug": false
		},
        "frontend": {
            "SecurityVersion": 1,
            "ProductID": 3,
            "UniqueID": "6b2822ac2585040d4b9397675d54977a71ef292ab5b3c0a6acceca26074ae585",
            "SignerID": "5826218dbe96de0d7b3b1ccf70ece51457e71e886a3d4c1f18b27576d22cdc74"
        }
    }
```

When you start your service, you need to pass in a couple of configuration parameters through environment variables.
Make sure that you match the service's name in the manifest with the `EDG_MARBLE_TYPE` (Coordinator was started with `EDG_COORDINATOR_MESH_ADDR=localhost:2001`):

```bash
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=frontend EDG_MARBLE_UUID_FILE=$PWD/uuid EDG_MARBLE_DNS_NAMES=localhost erthost enclave.signed
```
