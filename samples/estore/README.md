# Using EStore with a monotonic counter for rollback protection

This example shows how you can use [EStore](https://github.com/edgelesssys/estore) in an EGo Marble to store sensitive information in a structured way.
The encryption key is managed by the MarbleRun Coordinator.

Optionally, EStore can use a monotonic counter provided the the Coordinator for rollback protection.

Before proceeding, you should have successfully run the [helloworld sample](../helloworld).

**Note:** You can run this example on any hardware by simulating the enclave through setting `OE_SIMULATION=1` as environment variable. This might help you to get started with the development of confidential apps. However, please notice that this bypasses any security. Detailed information on how to develop secure Marbles can be found in [MarbleRun's documentation](https://docs.edgeless.systems/marblerun/workflows/add-service).

You can build and sign the example (or your app) like this:

```sh
ego-go build -tags marblerun_ego_enclave
ego sign estore-sample
```

Get the enclave's unique ID aka `MRENCLAVE` with

```sh
ego uniqueid estore-sample
```

and set it as `UniqueID` in `manifest.json`.

Next, use the `erthost` command to start the Coordinator in a local enclave:

```sh
erthost ../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client API (port 4433) and a mesh API (port 2001). While your Marble activates itself via the mesh API, you can administrate the Coordinator via the client API.

You can now upload the manifest to the Coordinator's client API:

```sh
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

Finaly, you can run the helloworld Marble (or whatever Marble you just created) with the `ego marblerun` command. You need to set `EDG_MARBLE_TYPE` to a Marble that was defined in the `manifest.json`. In this example, the manifest defines a single Marble, which is called "estore-marble".
You also need to set the Coordinator client API address so the Marble can call the monotonic counter API.

```sh
EDG_COORDINATOR_CLIENT_ADDR=localhost:4433 EDG_MARBLE_TYPE=estore-marble ego marblerun estore-sample
```

EGo starts the Marble, which will then connect itself to the mesh API of the Coordinator.
After activation, it will add a new value to the store and print all values added so far.
You can run the Marble multiple times.
You can see the rollback protection in action if you copy the `db` folder at some point in time, run the Marble again, and then copy the folder back.
The Marble will refuse to open the old DB state.
