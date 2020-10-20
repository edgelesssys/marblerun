# Remote Attestation

Remote attestation enables a host to verify it is running a certain piece of software on certain trusted hardware. 
Our Coordinator uses this to verify any marble before integrating it into the mesh. 
It can and should also be used by any client to verify that the Coordinator is running a valid instance on hardware the client trusts.
For more technical information see https://eprint.iacr.org/2016/086.pdf chapter 5.8