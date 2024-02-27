# Setting a manifest

After you've [defined a manifest](define-manifest.md), use it to initialize your MarbleRun deployment.

Set the manifest using the MarbleRun CLI:

```bash
marblerun manifest set manifest.json $MARBLERUN
```

The command first performs [remote attestation on the Coordinator](../features/attestation.md#coordinator-deployment) before uploading the manifest.
If successful, the TLS root certificate of the Coordinator is saved for future connections with the MarbleRun instance.
This ensures you are always talking to the same instance the manifest was uploaded to.

:::info

By default the certificate is saved to `$XDG_CONFIG_HOME/marblerun/coordinator-cert.pem`,
or `$HOME/.config/marblerun/coordinator-cert.pem` if `$XDG_CONFIG_HOME` isn't set.
Subsequent CLI commands will try loading the certificate from that location.
Use the `--coordinator-cert` flag to choose your own location to save or load the certificate.

:::

If the manifest contains a `RecoveryKeys` entry, you will receive a JSON reply including the recovery secrets, encrypted with the public keys supplied in `RecoveryKeys`.

:::caution

Keep these values somewhere safe. Without it, you can't [recover the Coordinator](../features/recovery.md).

:::
