# How to create a C++ Marble
This sample shows how to build a confidential C++ application and run it in Marblerun. This can serve you as a blueprint for making existing applications Marblerun-ready or creating new creating new [Marbles](https://www.marblerun.sh/docs/getting-started/marbles/). If you haven't already, [setup Marblerun](../../BUILD.md#build) to get ready.

The directory `app` contains the application code:

* `hello.cpp`: constitutes the actual program.
* `CMakeLists.txt`: Compiles the program into the static library `libapp.a`.

You can build the sample as follows:

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

Next, use the `erthost` command to start the Coordinator in a local simulated enclave:
```sh
OE_SIMULATION=1 erthost ../../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client API to instruct the Coordinator (port 4433) and a mesh API to communicate with your Marble (port 2001).

Once the Coordinator instance is running, you can upload the mainfest to the Coordinators client API:
```sh
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

To run the application, you need to set some environment variables. The Marbles type is defined in the `manifest.json`. In this sample, the manifest defines a single Marble, which is called "hello". The Marbles DNS name and the Coordinators address are used to establish a connection between the Coordinators mesh API and the Marble, and the UUID file stores a unique ID that enables a restart of the application.
```sh
EDG_MARBLE_TYPE=hello \
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 \
EDG_MARBLE_UUID_FILE=$PWD/uuid \
EDG_MARBLE_DNS_NAMES=localhost \
erthost build/enclave.signed
```
The app prints a "Hello world!" followd by the commandline arguments that are defined in the `manifest.json`.
