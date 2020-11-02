
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

Build the coordinator control plane:

```bash
mkdir build
cd build
cmake ..
make
```

Build the marble data plane:

```bash
cd marble
mkdir build
cd build
cmake ..
make
```

Build and install the libertmeshpremain library (optional):

```sh
cd libertmeshpremain
mkdir build
cd build
cmake ..
make
sudo make install
```

## Run

```bash
OE_SIMULATION=1 ./coordinator
```

## Test

### Unit Tests

```bash
go test -race ./...
```

### With SGX-DCAP attestation on enabled hardware (e.g., in Azure)

```bash
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/
```

### With SGX simulation mode

```bash
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/ -s
```

### Without SGX

```bash
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/ -s -noenclave
```