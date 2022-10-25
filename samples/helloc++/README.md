# How to create a C++ Marble

This example shows how to build a confidential C++ application and run it in MarbleRun. This can serve you as a blueprint for making existing applications MarbleRun-ready or creating new [Marbles](https://docs.edgeless.systems/marblerun/getting-started/marbles). If you haven't already, [setup MarbleRun](../../BUILD.md#build) to get ready.

**Note:** You can run this example on any hardware by simulating the enclave through setting `OE_SIMULATION=1` as environment variable. This might help you to get started with with the development of confidential apps. However, please notice that this bypasses any security. Detailed information on how to develop secure Marbles can be found in [MarbleRun's documentation](https://docs.edgeless.systems/marblerun/workflows/add-service).

The directory `app` contains the application code:

* `hello.cpp`: constitutes the actual program.
* `CMakeLists.txt`: Compiles the program into the static library `libapp.a`.

You can build the example as follows:

```sh
mkdir build
cd build
cmake ..
make
```

Then get the enclave's unique ID aka `MRENCLAVE`

```sh
oesign dump -e enclave.signed | grep mrenclave
```

and set it as `UniqueID` in `manifest.json`.

Next, use the `erthost` command to start the Coordinator in a local enclave:

```sh
erthost ../../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client REST API (port 4433) and a mesh API (port 2001). While the Coordinator and your Marble communicate via the mesh API, you can administrate the Coordinator via the REST API.

Once the Coordinator instance is running, you can upload the manifest to the Coordinator's client API:

```sh
curl -k --data-binary @../manifest.json https://localhost:4433/manifest
```

To run the application, you need to set some environment variables. The type of the Marble is defined in the `manifest.json`. In this example, the manifest defines a single Marble, which is called "hello". The Marble's DNS name and the Coordinator's address are used to establish a connection between the Coordinator's mesh API and the Marble. Further, the UUID file stores a unique ID that enables a restart of the application.

```sh
EDG_MARBLE_TYPE=hello \
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 \
EDG_MARBLE_UUID_FILE=$PWD/uuid \
EDG_MARBLE_DNS_NAMES=localhost \
erthost enclave.signed
```

The app prints a "Hello world!" followed by the command line arguments that are defined in the `manifest.json`.
