# C++ sample
This sample shows how to build a confidential C++ application and run it in Murblerun. This should serve as a blueprint for making existing applications Murblerun-ready or creating new ones.

The directory `app` contains the application code:

* `hello.cpp`: constitutes the actual program.
* `CMakeLists.txt`: Compiles the program into the static library `libapp.a`.

You can build the sampe as follows:

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

After you have [started a Coordinator instance](../../BUILD.md#run-the-coordinator) with `EDG_COORDINATOR_MESH_ADDR=localhost:2001` and [initialized it with the Manifest](../../BUILD.md#create-a-manifest), you can run your application:

```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=hello EDG_MARBLE_UUID_FILE=$PWD/uuid EDG_MARBLE_DNS_NAMES=localhost erthost enclave.signed
```

This app will then serve HTTP on port 8080:

```sh
$ curl http://localhost:8080
Hello world!
Commandline arguments: [foo bar]
```