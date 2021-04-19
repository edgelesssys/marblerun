
# Build and Development Guide

## Repo layout

Marblerun is written entirely in Go and builds on Edgeless RT, which is written largely in C/C++.

### Control Plane

* [`coordinator`](coordinator):
    * [`config`](coordinator/config): Environment variables for configuration
    * [`core`](coordinator/core): Provides the gRPC API for Marbles and HTTP-REST API for clients
    * [`quote`](coordinator/quote): Provides remote attestation quotes
    * [`rpc`](coordinator/rpc): Protobuf definitions for the control plane <-> data plane communication.
    * [`server`](coordinator/server): Provides the gRPC and HTTP server

### Data Plane

* [`marble`](marble):
	* [`config`](marble/config): Environment variables for configuration
	* [`premain`](marble/config): The data plane code written in Go

## Build

*Prerequisite*: [Edgeless RT](https://github.com/edgelesssys/edgelessrt) is installed and sourced.

Build the coordinator control plane and marble test applications.

```bash
mkdir build
cd build
cmake ..
make
```

## Run

### Run the Coordinator

```bash
OE_SIMULATION=1 erthost build/coordinator-enclave.signed
```

Per default, the Coordinator starts with the following default values. You can set your desired configuration by setting the environment variables.

| Setting | Default Value | Environment Variable |
| --- | --- | --- |
| the listener address for the gRPC server | localhost:2001 |  EDG_COORDINATOR_MESH_ADDR |
| the listener address for the HTTP server | localhost: 4433 | EDG_COORDINATOR_CLIENT_ADDR |
| the DNS names for the cluster’s root certificate | localhost | EDG_COORDINATOR_DNS_NAMES |
| the file path for storing sealed data | $PWD/marblerun-coordinator-data | EDG_COORDINATOR_SEAL_DIR |

*Note*: The Coordinator's state is sealed to `$PWD/marblerun-coordinator-data/sealed_data`. If you want a fresh restart remove this file first: `rm $PWD/marblerun-coordinator-data/sealed_data`.

### Create a Manifest

See the [`how to add a service`](https://marblerun.sh/docs/tasks/add-service/) documentation for more information on how to create a Manifest.
You can find the enclave's specific values (MRENCLAVE, MRSIGNER, etc.) in `build/marble-test-config.json`

Here is an example that has only the `SecurityVersion` and `ProductID` set:

```json
{
	"Packages": {
		"backend": {
			"SecurityVersion": 1,
			"ProductID": 1
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
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
					"ROOT_CA": "{{ pem .Marblerun.RootCA.Cert }}",
					"SEAL_KEY": "{{ hex .Marblerun.SealKey }}",
					"MARBLE_CERT": "{{ pem .Marblerun.MarbleCert.Cert }}",
					"MARBLE_KEY": "{{ pem .Marblerun.MarbleCert.Private }}"
				}
			}
	    }
	}
}
```

Save it in a file called `manifest.json` and upload it to the Coordinator with curl in another terminal:

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

* *Note*: Per default, a Marble starts with the following default values. You can set your desired configuration by setting the environment variables.

	| Setting | Default Value | Environment Variable |
	| --- | --- | --- |
	| network address of the Coordinator’s API for Marbles | localhost:2001 |  EDG_MARBLE_COORDINATOR_ADDR |
	| reference on one entry from your Manifest’s `Marbles` section | - (this needs to be set every time) | EDG_MARBLE_TYPE |
	| local file path where the Marble stores its UUID | $PWD/uuid | EDG_MARBLE_UUID_FILE |
	| DNS names the Coordinator will issue the Marble’s certificate for | $EDG_MARBLE_TYPE | EDG_MARBLE_DNS_NAMES |
## Marble-Injector

By default a Marblerun installation ships with a Kubernetes [MutatingAdmissionWebhook](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook).
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

### Unit Tests

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

You can build the docker image of the coordinator by providing a signing key:

```bash
openssl genrsa -out private.pem -3 3072
docker buildx build --secret id=signingkey,src=private.pem --target release --tag ghcr.io/edgelesssys/coordinator -f dockerfiles/Dockerfile.coordinator .
```

You can build the docker image of the marble-injector as follows:

```bash
docker buildx build --tag ghcr.io/edgelesssys/marble-injector -f dockerfiles/Dockerfile.marble-injector .
