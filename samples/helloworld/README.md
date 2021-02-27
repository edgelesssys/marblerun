# helloworld sample
This sample shows how to build a confidential Go application with [EGo](https://ego.dev) and run it in Marblerun. This should serve as a blueprint for making existing applications Marblerun-ready or creating new ones. Detailed instructions for setting up Marblerun are omitted for brevity. Please refer to the [documentation](https://marblerun.sh/docs/introduction/) for that.


You can build the sample as follows:
```sh
ego-go build
ego sign helloworld
```

Then get the enclave's unique ID aka MRENCLAVE
```sh
ego uniqueid helloworld
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
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=hello EDG_MARBLE_UUID_FILE=$PWD/uuid EDG_MARBLE_DNS_NAMES=localhost ego marblerun helloworld
```

This app will then serve HTTP on port 8080:
```sh
$ curl http://localhost:8080
Hello world!
Commandline arguments: [foo bar]
```
