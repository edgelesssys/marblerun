# Edgeless Mesh


![logo](docs/assets/logo_text.png)

[![Actions Status](https://github.com/edgelesssys/coordinator/workflows/Unit%20Tests/badge.svg)](https://github.com/edgelesssys/coordinator/actions)

[Edgeless Mesh](https://www.edgeless.systems/) is a framework for creating distributed confidential computing apps. Build your confidential microservices with [Edgeless RT](https://github.com/edgelesssys/edgelessrt), distribute them with Kubernetes and let Edgeless Mesh take care of the rest. Deploy end-to-end secure and verifiable AI pipelines or crunch on sensitive big data in the cloud. Confidential computing at scale has never been easier. 

Edgeless Mesh guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON. Edgeless Mesh verifies the integrity of services, bootstraps them, and sets up encrypted connections between them.

If a serivce fails, Edgeless Mesh will seamlessly substitute it with respect to the rules defined in the manifest.  

To keep things simple, Edgeless Mesh acts as certificate authority and issues one concise remote attestation statement for your whole distributed app. This can be used by anyone to verify the integrity of your distributed app. 

Edgeless Mesh is the service mesh for the age of confidential computing.

Key features of Edgeless Mesh are:

* Authentication and integrity verification of microservices
* Provisioning of certificates, configurations, and application artifacts
* Remote attestation for the confidentiallity and integrity over the whole mesh network.

## Overview

![overview](docs/assets/overview.svg)

## Quickstart and documentation

You can deploy your confidential computing application with Mesh with ease. See the [Getting Started Guide](TODO) for how.

For more comprehensive documentation, start with the [Mesh docs](TODO)

## Roadmap

Future development and visionary features for Edgeless Mesh:

* Authentication for the ClientAPI of Edgeless Mesh
* Support for LKL/Graphene
* Distribution of the Control Plane to mitigate against a single point of failure

## Build

To build the Coordinator control plane:

```bash
mkdir build
cd build
cmake ..
make
```

To build the data plane libraries and test applications:

```bash
cd marble
mkdir build
cd build
cmake ..
make
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

### SGX2 with DCAP Attestation

```bash
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/
```

### SGX in Simulation Mode

```bash
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/ -s
```

### NoEnclave

```bash
go test ./test/ -v -tags integration --args -c ../build/ -m ../marble/build/ -s -noenclave
```

## Examples

### Hello World

TODO

### Confidential Emoji Voting

We have evolved the [emojivoto](https://github.com/edgelesssys/emojivoto) microservice demo into a confidential computing application.

