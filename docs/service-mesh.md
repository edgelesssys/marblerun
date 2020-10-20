# Confidential Service Mesh

A service mesh is a dedicated infrastructure layer for facilitating service-to-service communications between microservices.
In the world of confidential computing, we are talking about confidential microservices.
On top of the usual features that come with a service mesh, a confidential microservice architecture has additional challenges that a confidential service mesh needs to address:

* How to authenticated services to each other using remote attestation?
* How to authenticate a microservice architecture to the outside world with remote attestation?
    * How to do remote attestation with a distributed application?
    * How to do remote attestation with heterogeneous hardware in a cluster?
    * How to provide authentication between clients and the application on the trusted computing base.
* How to seal data that services can be restarted and migrated on different nodes?

In short, a confidential microservice should implement an infrastructure layer that enables a confidential microservice application to be used, managed, and deployed with the ease of a confidential monolith.

## Implementation

Most general-purpose service meshes are implemented using a sidecar proxy.
These proxies intercept and control all inbound and outbound network communication between microservices in the service mesh.
They are often referred to as the data plane, in relation to the so-called control plane.
The control plane manages and configures proxies to route traffic, enforce policies, and collect telemetry.

In terms of the microservice architecture, the service and its sidecar proxy form a single atomic instance.
That means communications between them can be neglected and the sidecar is entirely transparent to its service.
Confidential applications require a more careful evaluation of the implications the service mesh layer has on the application's security properties.

EdgelessMesh implements a confidential service mesh by injecting the data-plane logic directly into the service's secure enclave.
That way we can ensure the confidentiality and integrity of communications from end-to-end between confidential services.
A sidecar proxy could only ensure the confidentiality of data between the proxy endpoints but would expose data in the communication from sidecar to service.

Edgeless Mesh guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON. Edgeless Mesh verifies the integrity of services, bootstraps them, and sets up encrypted connections between them.
To keep things simple, Edgeless Mesh acts as certificate authority and issues one concise remote attestation statement for your whole distributed app. This can be used by anyone to verify the integrity of your distributed app. 