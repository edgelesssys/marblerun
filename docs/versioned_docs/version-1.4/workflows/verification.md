# Verifying a deployment

The Coordinator provides an API for clients to verify the identity and integrity of the Coordinator itself and the deployed Marbles.

Specifically, the Coordinator exposes the `/quote` endpoint that returns a quote and a certificate chain consisting of a root CA and an intermediate CA. The root CA is fixed for the lifetime of your deployment, while the intermediate CA changes in case you [update](../workflows/update-manifest.md) the packages specified in your manifest. The Coordinator also makes the effective manifest available via the `/manifest` endpoint. In TLS connections with this endpoint, the Coordinator uses its root CA and intermediate CA. Learn more about this concept in the [Attestation](../features/attestation.md) section.

## Verifying the quote and the manifest using the CLI

The `marblerun manifest verify` command uses the two endpoints described above. It first verifies the Coordinator's quote according to a given policy and then checks that the expected `manifest.json` is in effect. 

:::info

You need to [install and configure a quote provider](../getting-started/installation.md#install-the-marblerun-cli) before you can use the command.

:::

The policy includes the Coordinator's `UniqueID` or the tuple `ProductID`, `SecurityVersion`, and `SignerID`. `UniqueID` and `SignerID` are also known as `MRENCLAVE` and `MRSIGNER` in SGX terminology. The policy for a given Coordinator is generated at build time and written to a file named `coordinator-era.json`. This file ships with every release of MarbleRun. You can find the policy file for the latest MarbleRun release at `https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json`

The command is used as follows:

```bash
marblerun manifest verify manifest.json $MARBLERUN
```

If successful, the certificates of the root CA and the intermediate CA are saved for future connections. This ensures you are always talking to the same verified instance.

:::info

By default, the command will save the Coordinators certificate chain to `$XDG_CONFIG_HOME/marblerun/coordinator-cert.pem`,
or `$HOME/.config/marblerun/coordinator-cert.pem` if `$XDG_CONFIG_HOME` is not set.
Subsequent CLI commands will try loading the certificate from that location.
Use the `--coordinator-cert` flag to choose your own location to save or load the certificate.

:::

:::info

The flag `--era-config` lets you optionally specify a custom policy for the verification of the quote. See the [documentation of the command](../reference/cli.md#marblerun-manifest-verify) for details.

:::
