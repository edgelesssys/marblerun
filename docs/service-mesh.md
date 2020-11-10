# Confidential Service Mesh

A service mesh is an infrastructure layer for managing, observing, and securing communications in a container-based cluster. In the Kubernetes world, [Istio](https://istio.io), [HashiCorp Consul](https://www.consul.io/), and [Linkerd](https://linkerd.io/) are the most popular general-purpose service meshes.

When we started looking into the concept of *confidential microservices*, we realized that there are additional challenges and requirements for service meshes in the conext of confidential computing.

* How to make an entire cluster or distributed app verifiable in a meaningful way from the outside?
* How to establish secure connections to a distributed app based on this?
* How to establish secure connections between services within a cluster based on remote attestation?
* How to securely and safely restart and migrate services between nodes?

Ultimately, a *confidential service mesh* should enable *distributed confidential apps* that can be used, managed, and deployed with the ease of a *confidential monolith*.

## Approach

Most general-purpose service meshes are implemented using so-called *sidecars*. The most prevalent sidecar is probably [Envoy](https://www.envoyproxy.io/).
In essence, sidecars are network proxies that are injected into *pods* running application containers. Sidecars observe, control, and often encrypt the network communication between application containers. Sidecars are often referred to as the data plane, in relation to the so-called control plane.
The control plane manages and configures the sidecars to route traffic, enforce policies, and collect stats.

Security-wise, conventional service meshes focus on protecting data in transit between application containers.
In contrast, distributed confidential apps require a more comprehensive approach and careful consideration of security implications.

In summary, Marblerun takes the following approach.

* Instead of relying on separate sidecars, Marblerun injects the data-plane logic directly into the application logic running inside secure enclaves. Through this tight coupling, secure connections always terminate inside secure enclaves. We refer to containers running such enclaves as *marbles*.
* Before bootstrapping marbles, Marblerun verifies their integrity using Intel SGX remote attestation primitives. This way, Marblerun is able to guarantee that the topology of a  distributed confidential app adheres to the cluster's effective *manifest*. Such a manifest is defined in simple JSON and is set once.
* Marblerun acts as certificate authority for all marble-based services and issues one concise remote attestation statement for the entire cluster. This can be used by anyone to verify the integrity of a distributed confidential app.
