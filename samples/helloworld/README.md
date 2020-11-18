# helloworld sample
This sample shows how to build a confidential Go application and run it in Marblerun. This should serve as a blueprint for making existing applications Marblerun-ready or creating new ones. Detailed instructions for setting up Marblerun are omitted for brevity. Please refer to the [documentation]() for that.

The directory `app` contains the application code:
* `hello.go` constitutes the actual program.
* `mesh.go` takes care of contacting the Marblerun Coordinator and applying the received configuration. To make a Go app Marblerun-ready, place this file in its main package.

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

After you have started a Coordinator instance with `EDG_COORDINATOR_MESH_ADDR=localhost:2001` and initialized it with the Manifest, you can run your application:
```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=hello EDG_MARBLE_UUID_FILE=$PWD/uuid EDG_MARBLE_DNS_NAMES=localhost erthost enclave.signed
```

This app will then serve HTTP on port 8080:
```sh
$ curl http://localhost:8080
Hello world!
Commandline arguments: [foo bar]
```
