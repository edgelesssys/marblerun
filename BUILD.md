
# Build and development guide

## Repo layout

MarbleRun is written entirely in Go and builds on Edgeless RT, which is written largely in C/C++.

### Control plane

* [`coordinator`](coordinator):
  * [`core`](coordinator/core): Provides the gRPC API for Marbles and HTTP-REST API for clients
  * [`quote`](coordinator/quote): Provides remote attestation quotes
  * [`rpc`](coordinator/rpc): Protobuf definitions for the control plane <-> data plane communication
  * [`server`](coordinator/server): Provides the Marble and client API server

### Data plane

* [`marble`](marble):
  * [`config`](marble/config): Environment variables for configuration
  * [`premain`](marble/premain): The data plane code that prepares the Marble's environment

## Build

### With Docker

You can build the MarbleRun binaries with Docker by providing a signing key:

```bash
openssl genrsa -out private.pem -3 3072
export DOCKER_BUILDKIT=1
docker build --secret id=signingkey,src=private.pem --target export -o. - < dockerfiles/Dockerfile.coordinator
docker build -o. - < dockerfiles/Dockerfile.cli
```

### In your environment

*Prerequisites*:

* Ubuntu 20.04 or 22.04
* [Edgeless RT](https://github.com/edgelesssys/edgelessrt) is installed and sourced
* Go 1.21 or newer

Build the Coordinator control plane and Marble test applications:

```bash
mkdir build
cd build
cmake ..
make
```

## Run

Here's how to run the Coordinator and test Marbles.

### Run the Coordinator

```bash
OE_SIMULATION=1 erthost build/coordinator-enclave.signed
```

The Coordinator starts with the following default values. You can set your desired configuration by setting the environment variables.

| Setting | Default Value | Environment Variable |
| --- | --- | --- |
| the listener address for the Marble server | localhost:2001 |  EDG_COORDINATOR_MESH_ADDR |
| the listener address for the client-API server | localhost: 4433 | EDG_COORDINATOR_CLIENT_ADDR |
| the DNS names for the cluster’s root certificate | localhost | EDG_COORDINATOR_DNS_NAMES |
| the file path for storing sealed data | $PWD/marblerun-coordinator-data | EDG_COORDINATOR_SEAL_DIR |

*Note*: The Coordinator's state is sealed to `$PWD/marblerun-coordinator-data/sealed_data`. If you want a fresh restart remove this file first: `rm $PWD/marblerun-coordinator-data/sealed_data`.

### Create a Manifest

See the [how to add a service](https://docs.edgeless.systems/marblerun/workflows/add-service) documentation on how to create a Manifest.
You can find the test enclave's specific values (MRENCLAVE, MRSIGNER, etc.) in `build/marble-test-config.json`:

```bash
$ cat build/marble-test-config.json
{
        "SecurityVersion": 1,
        "ProductID": 1,
        "UniqueID": "ac923351e562a127e7d5f58eae0787d13a1309b09893f6b6eb9eda49b1758621",
        "SignerID": "233ac7711eba0f5b8c67c4abfef811bf8ff4cbca4fc7be6fb98e0dcd7a0ddad1"
}
```

Here's an example that has the `SecurityVersion`, `ProductID`, and `SignerID` set:

```json
{
  "Packages": {
    "backend": {
      "Debug": true,
      "SecurityVersion": 1,
      "ProductID": 1,
      "SignerID": "233ac7711eba0f5b8c67c4abfef811bf8ff4cbca4fc7be6fb98e0dcd7a0ddad1"
    }
  },
  "Infrastructures": {
    "localhost": {}
  },
  "Marbles": {
    "server" : {
      "Package": "backend",
      "Parameters": {
        "Argv": [
          "./marble",
          "serve"
        ],
        "Env": {
          "ROOT_CA": "{{ pem .MarbleRun.RootCA.Cert }}",
          "MARBLE_CERT": "{{ pem .MarbleRun.MarbleCert.Cert }}",
          "MARBLE_KEY": "{{ pem .MarbleRun.MarbleCert.Private }}"
        }
      }
    },
    "client": {
      "Package": "backend",
      "Parameters": {
        "Argv": [
          "./marble"
        ],
        "Env": {
          "ROOT_CA": "{{ pem .MarbleRun.RootCA.Cert }}",
          "MARBLE_CERT": "{{ pem .MarbleRun.MarbleCert.Cert }}",
          "MARBLE_KEY": "{{ pem .MarbleRun.MarbleCert.Private }}"
        }
      }
    }
  }
}
```

**Replace the `SignerID` with YOUR value from `build/marble-test-config.json`**

*Note*: `Debug` is set to `true` here so that this example works with SGX debug enclaves. This is not secure for production.

Save the Manifest in a file called `manifest.json` and upload it to the Coordinator with curl in another terminal:

```bash
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

### Run the Marbles

Run a simple application.

* Server:
    Run the server service in a new terminal:

    ```bash
    EDG_MARBLE_TYPE=server EDG_MARBLE_UUID_FILE=$PWD/server_uuid EDG_TEST_ADDR=localhost:8001 OE_SIMULATION=1 erthost build/marble-test-enclave.signed
    ```

    You should see: `[...] starting server`.

    In the coordinator-terminal you should see: `Successfully activated new Marble of type 'server: ...'`

* Client:
    Run the client service in a new terminal:

    ```bash
    EDG_MARBLE_TYPE=client EDG_MARBLE_UUID_FILE=$PWD/client_uuid EDG_TEST_ADDR=localhost:8001 OE_SIMULATION=1 erthost build/marble-test-enclave.signed
    ```

    You should see: `[...] Successful connection to Server: 200 OK`

    In the coordinator-terminal you should see `Successfully activated new Marble of type 'client: ...'`

* *Note*: A Marble starts with the following default values. You can set your desired configuration by setting the environment variables.

  | Setting | Default Value | Environment Variable |
  | --- | --- | --- |
  | network address of the Coordinator’s API for Marbles | localhost:2001 |  EDG_MARBLE_COORDINATOR_ADDR |
  | reference on one entry from your Manifest’s `Marbles` section | - (this needs to be set every time) | EDG_MARBLE_TYPE |
  | local file path where the Marble stores its UUID | $PWD/uuid | EDG_MARBLE_UUID_FILE |
  | DNS names the Coordinator will issue the Marble’s certificate for | localhost | EDG_MARBLE_DNS_NAMES |

## Marble-Injector

By default a MarbleRun installation ships with a Kubernetes [MutatingAdmissionWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook).
The admission controller monitors selected namespaces of the cluster and injects the data-plane configuration into Deployments, Pods, etc.
The marble-injector is only useful in a Kubernetes environment.

You can build the marble-injector with:

```bash
mkdir build
cd build
cmake ..
make marble-injector
```

## Test

### Unit tests

```bash
go test -race ./...
```

### With SGX-DCAP attestation on enabled hardware (e.g., in Azure)

```bash
go test -v -tags integration ./test -b ../build
```

### With SGX simulation mode

```bash
go test -v -tags integration ./test -b ../build -s
```

### Without SGX

```bash
go test -v -tags integration ./test -b ../build -noenclave
```

## Docker image

You can build the Docker image of the Coordinator by providing a signing key:

```bash
openssl genrsa -out private.pem -3 3072
DOCKER_BUILDKIT=1 docker build --secret id=signingkey,src=private.pem --tag ghcr.io/edgelesssys/marblerun/coordinator - < dockerfiles/Dockerfile.coordinator
```

You can build the Docker image of the marble-injector as follows:

```bash
DOCKER_BUILDKIT=1 docker build --tag ghcr.io/edgelesssys/marblerun/marble-injector -f dockerfiles/Dockerfile.marble-injector .
```
