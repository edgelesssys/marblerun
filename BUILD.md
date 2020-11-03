
# Edgeless Mesh Build and Development Guide

## Repo layout

Edgeless Mesh is written entirely in Go and build on top of Edgeless RT that is written in C++.

### Control Plane

* [`coordinator`](coordinator):
    * [`config`](coordinator/config): Environment variables for configuration
    * [`core`](coordinator/core): Provides the gRPC API for marbles and HTTP-REST API for clients
    * [`quote`](coordinator/quote): Provides remote attestation quotes
    * [`rpc`](coordinator/rpc): Protobuf definitions for the control plane <-> data plane communication.
    * [`rpc`](coordinator/rpc): Provides the gRPC and HTTP server

### Data Plane

* [`marble`](marble): The data- plane code written in Go
* [`libertmeshpremain`](libertmeshpremain): Provides a pre-main routine written in Go for linking against non-Go applications.

## Build

Build the coordinator control plane and marble test applications:

```bash
mkdir build
cd build
cmake ..
make
```

For build and installing the libertmeshpremain library (required for services not written in Go) see the [`libertmeshpremain build instructions`](libertmeshpremain/README.md).

## Run

### Run the coordinator

```bash
EDG_COORDINATOR_MESH_ADDR=localhost:2001 EDG_COORDINATOR_CLIENT_ADDR=localhost:4433 EDG_COORDINATOR_DNS_NAMES=localhost EDG_COORDINATOR_SEAL_DIR=$PWD OE_SIMULATION=1 erthost build/coordinator-enclave.signed
```

*Note*: the coordinator's state is sealed to `$PWD/sealed_state`. If you want a fresh restart remove this file first: `rm $PWD/sealed_state`.

### Create a manifest

See the [`how to add a service`](TODO) documentation for more information on how to create a manifest.
You can find the enclave's specific values (MRENCLAVE, MRSIGNER, etc.) in `build/marble-test-config.json`

Here is an example that has only the `SecurityVersion` and `ProductID` set:

```json
{
	"Packages": {
		"backend": {
			"SecurityVersion": 1,
			"ProductID": [3]
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
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
					"ROOT_CA": "$$root_ca",
					"SEAL_KEY": "$$seal_key",
					"MARBLE_CERT": "$$marble_cert",
					"MARBLE_KEY": "$$marble_key"
				}
			}
	    }
	}
}
```

Save it in a file called `manifest.json` and upload it to the coordinator with curl in another terminal:

```bash
curl --silent -k -X POST -H  "Content-Type: application/json" --data-binary @manifest.json "https://localhost:4433/manifest"
```

### Run the marbles

Run a simple client-server application.

* Server:
    Run the server service in a new terminal:

    ```bash
    EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=server EDG_MARBLE_UUID_FILE=$PWD/server_uuid EDG_MARBLE_DNS_NAMES=localhost EDG_TEST_ADDR=localhost:8001 OE_SIMULATION=1 erthost build/marble-test-enclave.signed
    ```

    You should see: `[...] starting server`.

    In the coordinator-terminal you should see: `Successfully activated new Marble of type 'server: ...'`

* Client:
    Run the client service in a new terminal:

    ```bash
    EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=client EDG_MARBLE_UUID_FILE=$PWD/client_uuid EDG_MARBLE_DNS_NAMES=localhost EDG_TEST_ADDR=localhost:8001 OE_SIMULATION=1 erthost build/marble-test-enclave.signed
    ```

    You should see: `[...] Successful connection to Server: 200 OK`

    In the coordinator-terminal you should see `Successfully activated new Marble of type 'client: ...'`

## Test

### Unit Tests

```bash
go test -race ./...
```

### With SGX-DCAP attestation on enabled hardware (e.g., in Azure)

```bash
go test ./test/ -v -tags integration --args -b ../build/
```

### With SGX simulation mode

```bash
go test ./test/ -v -tags integration --args -b ../build/ -s
```

### Without SGX

```bash
go test ./test/ -v -tags integration --args -b ../build/ -s -noenclave
```