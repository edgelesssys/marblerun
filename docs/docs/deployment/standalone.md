# Standalone MarbleRun deployment

This guide walks you through deploying MarbleRun standalone.

## Prerequisites

* [EGo](https://github.com/edgelesssys/ego#install) is installed.

## Setup the Coordinator control plane

You can download the [latest release](https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-enclave.signed) of our Coordinator control plane on GitHub.
If you prefer to build from source please refer to our [build guide](https://github.com/edgelesssys/marblerun/blob/master/BUILD.md).

You can then run the Coordinator's enclave:

```bash
erthost build/coordinator-enclave.signed
```

Per default, the Coordinator starts with the following default values. You can set your desired configuration by setting the environment variables.

| Setting | Default Value | Environment Variable |
| --- | --- | --- |
| the listener address for the gRPC server | localhost:2001 |  EDG_COORDINATOR_MESH_ADDR |
| the listener address for the HTTP server | localhost: 4433 | EDG_COORDINATOR_CLIENT_ADDR |
| the DNS names for the cluster’s root certificate | localhost | EDG_COORDINATOR_DNS_NAMES |
| the file path for storing sealed data | $PWD/marblerun-coordinator-data | EDG_COORDINATOR_SEAL_DIR |

?> The Coordinator's state is sealed to `$PWD/marblerun-coordinator-data/sealed_data`. If you want a fresh restart remove this file first: `rm $PWD/marblerun-coordinator-data/sealed_data`.

The Coordinator is now in a pending state, waiting for a manifest.
See the [how to add a service](workflows/add-service.md) documentation for more information on how to create and set a manifest.

### Run your workloads

You first need to build your workloads together with our Marble data plane.
See our guides for building [EGo](building-services/ego.md), [Gramine](building-services/gramine.md), and [Occlum](building-services/occlum.md) workloads.

You can then run your Marble as follows:

```bash
EDG_MARBLE_TYPE=<your_marble_type> erthost <your_marble_binary>
```

Per default, a Marble starts with the following default values. You can set your desired configuration by setting the environment variables.

| Setting | Default Value | Environment Variable |
| --- | --- | --- |
| network address of the Coordinator’s API for Marbles | localhost:2001 |  EDG_MARBLE_COORDINATOR_ADDR |
| reference on one entry from your manifest’s `Marbles` section | - (this needs to be set every time) | EDG_MARBLE_TYPE |
| local file path where the Marble stores its UUID | $PWD/uuid | EDG_MARBLE_UUID_FILE |
| DNS names the Coordinator will issue the Marble’s certificate for | $EDG_MARBLE_TYPE | EDG_MARBLE_DNS_NAMES |
