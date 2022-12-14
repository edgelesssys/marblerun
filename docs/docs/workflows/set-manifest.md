# Setting a manifest

After you've [defined a manifest](define-manifest.md), use it to initialize your MarbleRun deployment.

Set the manifest using the MarbleRun CLI:

```bash
marblerun manifest set manifest.json $MARBLERUN
```

The command first performs [remote attestation on the Coordinator](../features/attestation.md#coordinator-deployment) before uploading the manifest.

If the manifest contains a `RecoveryKeys` entry, you will receive a JSON reply including the recovery secrets, encrypted with the public keys supplied in `RecoveryKeys`.

:::caution

Keep these values somewhere safe. Without it, you can't recover the Coordinator in case the SGX seal key changed.

:::
