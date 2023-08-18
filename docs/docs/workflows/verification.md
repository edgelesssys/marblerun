# Verifying a deployment

MarbleRun provides a simple HTTP REST API for clients to verify the confidentiality and integrity of the Coordinator and the deployed Marbles.

## Requirements

You need to [install and configure a quote provider](../getting-started/installation.md#install-the-marblerun-cli).

## Establishing trust in the Coordinator

MarbleRun exposes the `/quote` endpoint that returns a quote and a certificate chain consisting of a root and intermediate CA. The root CA is fixed for the lifetime of your deployment, while the intermediate CA changes in case you [update](../workflows/update-manifest.md) the packages specified in your manifest.

The simplest way to verify the quote is via the Edgeless Remote Attestation ([era](https://github.com/edgelesssys/era)) tool.

To verify the coordinator, `era` requires the Coordinator's UniqueID (or MRENCLAVE in SGX terms) or the tuple ProductID, SecurityVersion, SignerID (MRSIGNER) to verify the quote. `era` contacts the Coordinator, and receives an SGX quote from it which contains the actual UniqueID or ProductID/SecurityVersion/SignerID tuple of the running instance. The tool verifies it against the expected values defined in `coordinator-era.json` and can therefore determine if an authentic copy of the Coordinator is running, or if an unknown version is contacted.

In production, the expected values in `coordinator-era.json` would be generated when building the Coordinator and distributed to your clients. When you build MarbleRun from source, you can find the file in your build directory.
For testing with a pre-built release, there's a Coordinator image at `ghcr.io/edgelesssys/marblerun/coordinator`.
You can pull the corresponding `coordinator-era.json` file from the release page:

```bash
wget https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json
```

After installing `era`, you can verify the quote with the following command:

```bash
era -c coordinator-era.json -h $MARBLERUN -output-chain marblerun-chain.pem -output-root marblerun-root.pem -output-intermediate marblerun-intermedite.pem
```

After successful verification, you'll have `marblerun-chain.pem`, `marblerun-root.pem`, and `marblerun-intermediate.pem` in your directory. In case you want to pin against specific versions of your application, using the intermediate CA as a trust anchor is a good choice. Else you can pin against the root CA in which case different versions of your application can talk with each other. However, you may not be able to launch them if they don't meet the minimum `SecurityVersion` specified in your original or updated manifest.

## Verifying the manifest

Establishing trust with the service mesh allows you to verify the deployed manifest in the second step.
To that end, MarbleRun exposes the endpoint `/manifest`.
Using the CLI, you can get the manifest's signature and compare it against your local version of the manifest which should have been provided to you by the operator.

You can verify your local `manifest.json` against the Coordinator's version with the following command:

```bash
marblerun manifest verify manifest.json $MARBLERUN
```
