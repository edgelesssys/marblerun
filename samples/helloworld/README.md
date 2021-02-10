# helloworld sample
This sample shows how to build a confidential Go application with [ego](https://ego.dev) and run it in Marblerun. This should serve as a blueprint for making existing applications Marblerun-ready or creating new ones. Detailed instructions for setting up Marblerun are omitted for brevity. Please refer to the [documentation](https://marblerun.sh/docs/introduction/) for that.

The `hello.go` contains the application code:

You can build the sample as follows:
```sh
ego-go build
ego sign hello
```

Then get the enclave's unique ID aka MRENCLAVE
```sh
ego uniqueid hello
```
and set it as `UniqueID` in `manifest.json`.

After you have [started a Coordinator instance](../../BUILD.md#run-the-coordinator) with `EDG_COORDINATOR_MESH_ADDR=localhost:2001` and [initialized it with the Manifest](../../BUILD.md#create-a-manifest), you can run your application:
```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=hello EDG_MARBLE_UUID_FILE=$PWD/uuid EDG_MARBLE_DNS_NAMES=localhost ego marblerun hello
```

This app will then serve HTTP on port 8080:
```sh
$ curl http://localhost:8080
Hello world!
Commandline arguments: [foo bar]
```
