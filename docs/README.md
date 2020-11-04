# Edgeless Mesh

![logo](assets/mesh_text.png)

[Edgeless Mesh](https://www.edgeless.systems/) is a framework for creating distributed confidential-computing apps.

Build your confidential microservices with [Edgeless RT][edgelessrt], distribute them with Kubernetes on an SGX-enabled cluster, and let Edgeless Mesh take care of the rest. Deploy end-to-end secure and verifiable AI pipelines or crunch on sensitive big data in the cloud. Confidential computing at scale has never been easier.

Edgeless Mesh guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON. Edgeless Mesh verifies the integrity of services, bootstraps them, and sets up encrypted connections between them.

If a node fails, Edgeless Mesh will seamlessly substitute it with respect to the rules defined in the manifest.  

To keep things simple, Edgeless Mesh acts as certificate authority and issues one concise remote attestation statement for your whole distributed app. This can be used by anyone to verify the integrity of your distributed app.

Edgeless Mesh is the service mesh for the age of confidential computing.

Key features of Edgeless Mesh are:

:lock: Authentication and integrity verification of microservices

:package: Provisioning of certificates, configurations, and application artifacts

:globe_with_meridians: Remote attestation for the confidentiallity and integrity over the whole cluster.

![overview](assets/overview.svg)