# Graphene "Hello World!" sample (preload)
This sample shows how to run a [Graphene](https://github.com/oscarlab/graphene) application in Marblerun. In essence, you have to add the `premain` process as a preloaded library for LD_PRELOAD. `premain` will contact the Coordinator, set up the environment, and run the actual application. See the commented [hello.manifest.template](hello.manifest.template) for details.
## Requirements
First, get Graphene up and running. You can use either the [Building](https://graphene.readthedocs.io/en/latest/building.html) or [Cloud Deployment](https://graphene.readthedocs.io/en/latest/cloud-deployment.html) guide to build and initially setup Graphene.

Then, before you can run the sample, make sure you got the prerequisites for ECDSA remote attestation installed on your system. You can collectively install them with the following command:
```sh
sudo apt install libsgx-quote-ex-dev
```

## Build
You can build the sample as follows:
```sh
export GRAPHENEDIR=[PATH To Your Graphene Folder]
make
```
Then get `mr_enclave` from the build output and set it as `UniqueID` in `manifest.json`.

Note that compared to the `spawn` method for this sample, the argv arguments are defined during the build and cannot be changed afterwards without rebuilding your Graphene application. To adjust the provisioned argv arguments, you can change the entry `hello.argv` in the Makefile.

## Run
We assume that the Coordinator is run with the following environment variables:

- EDG_COORDINATOR_MESH_ADDR=localhost:2001
- EDG_COORDINATOR_CLIENT_ADDR=localhost:4433
- EDG_COORDINATOR_DNS_NAMES=localhost
- EDG_COORDINATOR_SEAL_DIR=$PWD

Once the [Coordinator instance is running](../../BUILD.md#run-the-coordinator), upload the manifest to the Coordinator:

```
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

Now we can run our application:

```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=hello EDG_MARBLE_UUID_FILE=uuid EDG_MARBLE_DNS_NAMES=localhost make run
```

## Troubleshooting
If you receive the following error message on launch:

```
aesm_service returned error: 30
load_enclave() failed with error -1
```

Make sure you installed the Intel AESM ECDSA plugins on your machine. You can do this by installing the `libsgx-quote-dev` mentioned in the requirements above:
