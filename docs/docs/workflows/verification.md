# Verifying a deployment

The Coordinator provides an API for clients to verify the identity and integrity of the Coordinator itself and the deployed Marbles.

Specifically, the Coordinator exposes the `/quote` endpoint that returns a quote and a certificate chain consisting of a root CA and an intermediate CA. The root CA is fixed for the lifetime of your deployment, while the intermediate CA changes in case you [update](../workflows/update-manifest.md) the packages specified in your manifest.

:::info

You need to [install and configure a quote provider](../getting-started/installation.md#install-the-marblerun-cli) on the machine that is verifying the quote.

:::

There are two recommended ways to verify the Coordinator's quote: The `marblerun manifest verify` command connects to the Coordinator *and* verifies its quote according to a given policy and then checks that the expected manifest is in effect. Alternatively, the standalone `era` tool can be used. It only performs the verification step. In both cases, the quote is verified against a given policy. This policy includes the Coordinator's `UniqueID` or the tuple `ProductID`, `SecurityVersion`, and `SignerID`. `UniqueID` and `SignerID` are also known as `MRENCLAVE` and `MRSIGNER` in SGX terminology.

:::info

The policy for a given Coordinator is generated at build time and written to a file named `coordinator-era.json`. This file ships with every release of MarbleRun. You can find the policy file for the latest MarbleRun release at `https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json`

:::

Both ways are detailed in the following.

## Verifying the quote and the manifest using the CLI

The Coordinator makes the effective manifest available via the `/manifest` endpoint.
The following CLI command first verifies the Coordinator's quote and then checks that the effective `manifest.json` matches the supplied local one.

```bash
marblerun manifest verify manifest.json $MARBLERUN
```

If successful, the TLS root certificate of the Coordinator is saved for future connections with the MarbleRun instance.
This ensures you are always talking to the same instance that you verified the manifest against.

:::info

The flag `--era-config` lets you optionally specify a custom policy for the verification of the quote. See the [documentation of the command](../reference/cli.md#marblerun-manifest-verify) for details.

:::

:::info

By default, the command will save the Coordinators certificate chain to `$XDG_CONFIG_HOME/marblerun/coordinator-cert.pem`,
or `$HOME/.config/marblerun/coordinator-cert.pem` if `$XDG_CONFIG_HOME` is not set.
Subsequent CLI commands will try loading the certificate from that location.
Use the `--coordinator-cert` flag to choose your own location to save or load the certificate.

:::

## Verifying the quote using the ERA tool

The `era` tool enables standalone verification of quotes. For example, it enables clients to establish trust into a MarbleRun deployment without having to install the MarbleRun CLI.
The following command verifies the Coordinator's quote against a given policy file `coordinator-era.json`. The policy file is to be distributed to clients via a trusted channel a priori.

```bash
era -c coordinator-era.json -h $MARBLERUN -output-chain marblerun-chain.pem -output-root marblerun-root.pem -output-intermediate marblerun-intermedite.pem
```

After successful verification, you'll have `marblerun-chain.pem`, `marblerun-root.pem`, and `marblerun-intermediate.pem` in your directory. In case you want to pin against specific versions of your application, using the intermediate CA as a trust anchor is a good choice. Else you can pin against the root CA in which case different versions of your application can talk with each other. However, you may not be able to launch them if they don't meet the minimum `SecurityVersion` specified in your original or updated manifest.
