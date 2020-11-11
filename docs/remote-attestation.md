# Remote Attestation

Remote attestation is a fundamental problem for a distributed confidential application.
To keep things simple, Marblerun acts as certificate authority and issues one concise remote attestation statement for your whole distributed app.
This can be used by anyone to verify the integrity of your distributed app.

To that end, the Coordinator provides a Client REST-API endpoint that allows any client to verify the topology of the distributed app adheres to the deployed manifest.
As part of the remote attestation statement the client also receives the root certificate of the Coordinator CA.
This allows any client to establish trust to the Coordinator and consequentially to all services in the mesh.
