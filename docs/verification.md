# Client-Side Verification

An important feature of Edgeless Mesh is providing the ability to verifying the confidentiality and integrity of the whole application on the client-side.
To that end, we provide a simple REST-API that clients can use before interacting with the application.

## Establishing Trust

The first step is to establish trust with the whole microservice mesh.
Therefore, Edgeless Mesh exposes the `/quote` endpoint that returns a quote and a root certificate for the whole mesh.
Verifying the quote can be done by manually, but to ease the process we provide the Edgeless Remote Attestation tools ([era](https://github.com/edgelesssys/era)) for this purpose:

```bash
go install github.com/edgelesssys/era/cmd/era
era -c mesh.config -h $EDG_COORDINATOR_ADDR -o mesh.crt
```

era requires the Coordinator's UniqueID and SignerID (or MRENCLAVE and MRSIGNER in SGX terms) to verify the quote.
In production, these would be generated when building *Coordinator* and distributed to your clients.
For testing, we have published a Coordinator image at `ghcr.io/edgelesssys/coordinator:latest`.
You can pull the corresponding `mesh.config` file from our release page:

```bash
    curl -s https://api.github.com/repos/edgelesssys/coordinator/releases/latest \
    | grep "mesh.config" \
    | cut -d '"' -f 4 \
    | wget -qi -
```

After successful verification, you'll have the trusted root certificate `mesh.crt` to use with your application.

## Verifing the Manifest

Establishing trust with the service mesh allows you to verify the deployed manifest in the second step.
To that end, Edgeless Mesh exposes the endpoint `/manifest`.
Using curl you can get the manifest's signature aka its sha256 hash:

```bash
curl --silent --cacert mesh.crt "https://$EDG_COORDINATOR_ADDR/manifest" | jq '.ManifestSignature' --raw-output
```

Compare this against your local version of the manifest:

```bash
sha256sum ./manifest.json
```