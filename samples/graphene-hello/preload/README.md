# Graphene "Hello World!" example (preload)
This example shows how to run a [Graphene](https://github.com/oscarlab/graphene) application in Marblerun. In essence, you have to add the `premain` process as a preloaded library for LD_PRELOAD. `premain` will contact the Coordinator, set up the environment, and run the actual application. See the commented [hello.manifest.template](hello.manifest.template) for details.
## Requirements
First, get Graphene up and running. You can use either the [Building](https://graphene.readthedocs.io/en/latest/building.html) or [Cloud Deployment](https://graphene.readthedocs.io/en/latest/cloud-deployment.html) guide to build and initially setup Graphene. You will need hardware with Intel SGX support.

Then, before you can run the example, make sure you got the prerequisites for ECDSA remote attestation installed on your system. You can collectively install them with the following command:
```sh
sudo apt install libsgx-quote-ex-dev
```

## Build
You can build the example as follows:
```sh
export GRAPHENEDIR=[PATH To Your Graphene Folder]
make
```
Then get `mr_enclave` from the build output and set it as `UniqueID` in `manifest.json`.

Note that compared to the `spawn` method for this example, the argv arguments are defined during the build and cannot be changed afterwards without rebuilding your Graphene application. To adjust the provisioned argv arguments, you can change the entry `hello.argv` in the Makefile.

## Run
Next, use the `erthost` command to start the Coordinator in a local enclave:
```sh
erthost ../../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client REST API (port 4433) and a mesh API (port 2001). While the Coordinator and your Marble communicate via the mesh API, you can administrate the Coordinator via the REST API.

Once the Coordinator instance is running, you can upload the manifest to the Coordinator's client API:
```
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

To run the application, you need to set some environment variables. The type of the Marble is defined in the `manifest.json`. In this example, the manifest defines a single Marble, which is called "hello". The Marble's DNS name and the Coordinator's address are used to establish a connection between the Coordinator's mesh API and the Marble. Further, the UUID file stores a unique ID that enables a restart of the application.

```sh
EDG_MARBLE_TYPE=hello \
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 \
EDG_MARBLE_UUID_FILE=uuid \
EDG_MARBLE_DNS_NAMES=localhost \
make run
```
