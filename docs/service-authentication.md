# Service Authentication

In a distributed confidential application it is of utmost importance to guarantee only trusted services are added to the mesh.
Imagine an adversary could spawn a malicious instance of a backend service that would retrieve part of the data flow through load balancing. Your genuine instances would still guarantee the confidentiality of the data they receive, but part of the data would be leaked to the adversary.

Marblerun verifies the identity and integrity of each newly spawned service before adding it to the service mesh.
A freshly spawned microservice (Marble in our terms) will try to register and activate itself by sending an activation request via gRPC to the Coordinator.
This request contains a  remote attestation quote, which allows the Coordinator to verify that the service adheres to the deployed manifest.
