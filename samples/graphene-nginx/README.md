# Graphene nginx sample
This sample is a slightly modified variant of the [Graphene nginx sample](https://github.com/oscarlab/graphene/tree/master/Examples/nginx). Changes are required to run it in Marblerun.

*Prerequisite*: Graphene is set up and the original nginx sample is working.

To marbleize the sample we edited [nginx.manifest.template](nginx.manifest.template). See comments starting with `MARBLERUN` for explanations of the required changes.

We also removed certificate generation from the Makefile because it will be provisioned by the Coordinator. See [manifest.json](manifest.json) on how this is specified.

We now build the sample as follows:
```sh
wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-graphene
make SGX=1
```

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
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=frontend EDG_MARBLE_UUID_FILE=uuid EDG_MARBLE_DNS_NAMES=localhost SGX=1 ./pal_loader nginx
```
