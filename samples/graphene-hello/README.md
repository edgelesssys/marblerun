# Graphene sample
This sample shows how to run a [Graphene](https://github.com/oscarlab/graphene) application in Marblerun. In essence, you have to add the `premain` process to the Graphene manifest. `premain` will contact the Coordinator, set up the environment, and run the actual application. See the commented [hello.manifest.template](hello.manifest.template) for details.

You can build the sample as follows:
```sh
export GRAPHENEDIR=[PATH To Your Graphene Folder]
make
```
Then get `mr_enclave` from the build output and set it as `UniqueID` in `manifest.json`.

We assume that the Coordinator is run with the following environment variables:

- EDG_COORDINATOR_MESH_ADDR=localhost:2001
- EDG_COORDINATOR_CLIENT_ADDR=localhost:4433
- EDG_COORDINATOR_DNS_NAMES=localhost
- EDG_COORDINATOR_SEAL_DIR=$PWD

Once the [Coordinator instance is running](../../BUILD.md#run-the-coordinator), upload the manifest to the Coordinator:

```
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

Now we can run our application:

```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=hello EDG_MARBLE_UUID_FILE=uuid EDG_MARBLE_DNS_NAMES=localhost make run
```
