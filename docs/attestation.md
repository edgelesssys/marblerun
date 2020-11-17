# Attestation

Hardware-rooted *remote attestation* is a key ingredient for distributed confidential apps. Without it, services couldn't trust each other and clients couldn't trust the app. Thus, Marblerun relies heavily on the *Data Center Attestation Primitives* (DCAP) of the latest SGX-enabled Intel Xeon processors. You can learn more about DCAP [here](https://download.01.org/intel-sgx/sgx-dcap/1.9/linux/docs/Intel_SGX_DCAP_ECDSA_Orientation.pdf). 

## Internal attestation of marbles

The Coordinator verifies the identity and integrity of each newly spawned marble before admitting it to the mesh.
A freshly spawned marble will try to register and activate itself by sending an activation request via gRPC to the Coordinator.
This request contains a remote attestation certificate (or "quote"), which allows the Coordinator to verify that the service adheres to the manifest in effect.

## External attestation of the app

To keep things simple, the Coordinator issues one concise remote-attestation statement for your whole distributed app. Technically, the statement resembles a regular TLS certificate chain with some extra info. (TLS is the protocol that is responsible for the lock in your browser's toolbar ;-). The chain ends at the root certificate authority (CA) of the provider of the secure hardware, which currently in almost all cases will be Intel.

Given the *Coordinator's* remote-attestation statement, external clients can verify that a distributed app adheres to a given manifest, i.e., that the app is running the expected software with the expected parameters on the expected secure hardware. Afterward, clients can establish secure TLS connections to the app and use it as normal. The Coordinator acts as CA for these connections and clients don't need to verify individual marbles. The steps required on the client-side are described [here](verification.md).

