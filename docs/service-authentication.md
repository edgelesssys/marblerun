# Service Authentication

In a distributed confidential application, it is critically important that only trusted and authenticated services can join the mesh. 
To this end, Marblerun verifies the identity and integrity of each newly spawned marble before adding it to the mesh.
A freshly spawned marble will try to register and activate itself by sending an activation request via gRPC to the *Coordinator*.
This request contains a remote attestation quote, which allows the *Coordinator* to verify that the service adheres to the effective manifest.
