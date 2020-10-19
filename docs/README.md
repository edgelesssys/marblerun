# Edgeless Mesh

![logo](assets/mesh_text.png)

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