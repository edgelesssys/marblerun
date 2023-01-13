# Gramine nginx example

This example is a slightly modified variant of the [Gramine nginx example](https://github.com/gramineproject/gramine/tree/master/CI-Examples/nginx). These changes are required to run it with MarbleRun.

*Prerequisite*: Gramine is installed on [release v1.3](https://github.com/gramineproject/gramine/releases/tag/v1.3.1) and the original nginx example is working. You will need hardware with Intel SGX support, and the Coordinator must not run in simulation mode.

To marbleize the example we edited [nginx.manifest.template](nginx.manifest.template). See comments starting with `MARBLERUN` for explanations of the required changes.

We also removed certificate generation from the Makefile because it will be provisioned by the Coordinator. See [manifest.json](manifest.json) on how this is specified.

We now build the example as follows:

```sh
openssl genrsa -3 -out enclave-key.pem 3072
make SGX=1
```

Start the Coordinator in a SGX enclave:

```sh
erthost ../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client REST API (port 4433) and a mesh API (port 2001). While the Coordinator and your Marble communicate via the mesh API, you can administrate the Coordinator via the REST API.

Once the Coordinator instance is running, you can upload the manifest to the Coordinator's client API:

```sh
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

The type of the Marble is defined in the `manifest.json`. In this example, the manifest defines a single Marble, which is called "frontend". To run the application, you need to set the `EDG_MARBLE_TYPE` environment variable to that name.

```sh
EDG_MARBLE_TYPE=frontend gramine-sgx nginx
```

From a new terminal, check if nginx is running properly:

```sh
curl -k https://localhost:8444
```
