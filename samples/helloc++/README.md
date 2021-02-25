# C++ sample
This sample shows how to build a confidential C++ application and run it in Marblerun. This should serve as a blueprint for making existing applications Marblerun-ready or creating new ones.

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

Then get the enclave's unique ID aka MRENCLAVE

```sh
oesign dump -e enclave.signed | grep mrenclave
```

and set it as `UniqueID` in `manifest.json`.

We assume that the Coordinator is run with the following environment variables:
- EDG_COORDINATOR_MESH_ADDR=localhost:2001
- EDG_COORDINATOR_CLIENT_ADDR=localhost:4433
- EDG_COORDINATOR_DNS_NAMES=localhost
- EDG_COORDINATOR_SEAL_DIR=$PWD

Once the [Coordinator instance is running](../../BUILD.md#run-the-coordinator), upload the manifest to the Coordinator:
```sh
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

Now we can run our application:
```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=hello EDG_MARBLE_UUID_FILE=$PWD/uuid EDG_MARBLE_DNS_NAMES=localhost erthost enclave.signed
```
