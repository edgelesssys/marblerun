# Gramine "Hello World!" example

This example shows how to run a [Gramine](https://github.com/gramineproject/gramine) application in MarbleRun. In essence, you have to add the `premain` process to the Gramine manifest. `premain` will contact the Coordinator, set up the environment, and run the actual application. See the commented [hello.manifest.template](hello.manifest.template) for details.

## Requirements

First, install Gramine on [release v1.3](https://github.com/gramineproject/gramine/releases/tag/v1.3.1). You will need hardware with Intel SGX support.

Then, before you can run the example, make sure you got the prerequisites for ECDSA remote attestation installed on your system. You can collectively install them with the following command:

```sh
sudo apt install libsgx-quote-ex-dev
```

## Build

You can build the example as follows:

```sh
openssl genrsa -3 -out enclave-key.pem 3072
make
```

Then get `mr_enclave` from the build output and set it as `UniqueID` in `manifest.json`.

## Run

Next, use the `erthost` command to start the Coordinator in a local enclave:

```sh
erthost ../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client REST API (port 4433) and a mesh API (port 2001). While the Coordinator and your Marble communicate via the mesh API, you can administrate the Coordinator via the REST API.

Once the Coordinator instance is running, you can upload the manifest to the Coordinator's client API:

```sh
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

The type of the Marble is defined in the `manifest.json`. In this example, the manifest defines a single Marble, which is called "hello". To run the application, you need to set the `EDG_MARBLE_TYPE` environment variable to that name.

```sh
EDG_MARBLE_TYPE=hello gramine-sgx hello
```
