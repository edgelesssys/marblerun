Edgeless Mesh
===

[![Actions Status](https://github.com/edgelesssys/coordinator/workflows/Unit%20Tests/badge.svg)](https://github.com/edgelesssys/coordinator/actions)

[Edgeless Mesh](https://www.edgeless.systems/) is a framework for creating distributed confidential computing apps. Build your confidential microservices with [Edgeless RT](https://github.com/edgelesssys/edgelessrt), distribute them with Kubernetes and let Edgeless Mesh take care of the rest. Deploy end-to-end secure and verifiable AI pipelines or crunch on sensitive big data in the cloud. Confidential computing at scale has never been easier. 

Edgeless Mesh guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON. Edgeless Mesh verifies the integrity of services, bootstraps them, and sets up encrypted connections between them.

If a serivce fails, Edgeless Mesh will seamlessly substitute it with respect to the rules defined in the manifest.  

To keep things simple, Edgeless Mesh acts as certificate authority and issues one concise remote attestation statement for your whole distributed app. This can be used by anyone to verify the integrity of your distributed app. 

Edgeless Mesh is the service mesh for the age of confidential computing.

Key features of Edgeless Mesh are:
* Authentication and integrity verification of services
* Distribution of secrets, configurations, certificates and keys
* Remote attestation for the confidentiallity and integrity over the whole mesh network.

## Overview
![overview](assets/overview.svg)

## Roadmap
Future development and visionary features for Edgeless Mesh:
* Authentication for the ClientAPI of Edgeless Mesh
* Distribution of the Control Plane to mitigate against a single point of failure


## Build
To build the Coordinator control plane:
```
mkdir build
cd build
cmake ..
make 
```

To build the data plane libraries and test applications:
```
cd marble
mkdir build
cd build
cmake ..
make
```

### Test
#### SGX
```
go test ./test/ -v --args -c ../build/ -m ../marble/build/
```
#### Simulation
```
go test ./test/ -v --args -c ../build/ -m ../marble/build/ -s
```
#### NoEnclave
```
go test ./test/ -v --args -c ../build/ -m ../marble/build/ -s -noenclave
```

## Hello World
TODO

## Emojivoto Demo
We have evolved the [emojivoto](https://github.com/edgelesssys/emojivoto) microservice demo into a confidential computing application.