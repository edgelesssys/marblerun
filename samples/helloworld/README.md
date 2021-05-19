# How to build a helloworld Marble
This example shows how to build a confidential Go application with [EGo](https://ego.dev) and run it in Marblerun. This can serve you as a blueprint for making existing applications Marblerun-ready or creating new [Marbles](https://www.marblerun.sh/docs/getting-started/marbles/). If you haven't already, [setup Marblerun](../../BUILD.md#build) and EGo to get ready.

**Note:** You can run this example on any hardware by simulating the enclave through setting `OE_SIMULATION=1` as environment variable. This might help you to get started with with the development of confidential apps. However, please notice that this bypasses any security. Detailed information on how to develope secure Marbles can be found in [Marbleruns documentation](https://www.marblerun.sh/docs/workflows/add-service/).

You can build and sign the example (or your app) like this:
```sh
ego-go build
ego sign hello
```

Get the enclave's unique ID aka `MRENCLAVE` with
```sh
ego uniqueid hello
```
and set it as `UniqueID` in `manifest.json`.

Next, use the `erthost` command to start the Coordinator in a local simulated enclave:
```sh
erthost ../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client REST API (port 4433) and a mesh API (port 2001). While the Coordinator and your Marble communicate via the mesh API, you can administrate the Coordinator via the REST API.

You can now upload the manifest to the Coordinator's client API:
```sh
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

Finaly, you can run the helloworld Marble (or whatever Marble you just created) with the `ego marblerun` command. You just need to set `EDG_MARBLE_TYPE` to a Marble that was defined in the `manifest.json`. In this example, the manifest defines a single Marble, which is called "hello".
```sh
EDG_MARBLE_TYPE=hello ego marblerun hello
```
EGo starts the Marble, which will then connect itself to the mesh API of the Coordinator.

The helloworld example app will then serve HTTP on port 8080:
```sh
$ curl http://localhost:8080
Hello world!
Commandline arguments: [foo bar]
```
