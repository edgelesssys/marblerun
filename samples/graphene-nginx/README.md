# Graphene nginx example
This example is a slightly modified variant of the [Graphene nginx example](https://github.com/oscarlab/graphene/tree/master/Examples/nginx). These changes are required to run it in Marblerun.

*Prerequisite*: Graphene is set up and the original nginx example is working. You will need hardware with Intel SGX support.

To marbleize the example we edited [nginx.manifest.template](nginx.manifest.template). See comments starting with `MARBLERUN` for explanations of the required changes.

We also removed certificate generation from the Makefile because it will be provisioned by the Coordinator. See [manifest.json](manifest.json) on how this is specified.

We now build the example as follows:
```sh
wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-graphene
export GRAPHENEDIR=[PATH To Your Graphene Folder]
make SGX=1
```

Start the Coordinator in a local simulated enclave:
```sh
erthost ../../../build/coordinator-enclave.signed
```

The Coordinator exposes two APIs, a client API to instruct the Coordinator (port 4433) and a mesh API to communicate with your Marble (port 2001).

Once the Coordinator instance is running, you can upload the mainfest to the Coordinators client API:
```
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

To run the application, you need to set some environment variables. The Marbles type is defined in the `manifest.json`. In this example, the manifest defines a single Marble, which is called "frontend". The Marbles DNS name and the Coordinators address are used to establish a connection between the Coordinators mesh API and the Marble, and the UUID file stores a unique ID that enables a restart of the application.

```sh
EDG_MARBLE_TYPE=frontend \
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 \
EDG_MARBLE_UUID_FILE=uuid \
EDG_MARBLE_DNS_NAMES=localhost \
SGX=1 \
./pal_loader nginx
```
