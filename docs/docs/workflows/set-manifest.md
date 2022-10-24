# Setting a manifest

The manifest is a JSON document that defines which services span the mesh and how they should be configured.
It further defines what Infrastructure providers are allowed.
You can set a manifest through MarbleRun's Client HTTP REST API.
The endpoint for all manifest operations is `/manifest`.

See [Defining a manifest](workflows/define-manifest.md) to learn how to define a manifest.

To set the manifest we can use the command line interface, which performs remote attestation on the Coordinator before uploading the manifest.
For further information see [Verifying a deployment](workflows/verification.md)

```bash
marblerun manifest set manifest.json $MARBLERUN
```

If the manifest contains a `RecoveryKeys` entry, you will receive a JSON reply including a recovery secret, encrypted with the public key supplied in `RecoveryKeys`. The reply will look like this, with `[base64]` as your encrypted recovery secret.
This secret is the Coordinator's state-encryption key.

`{"EncryptionKey":"[base64]"}`

!> It is important that you keep this value stored somewhere safe. Without it, you will not be able to perform a recovery step in case the SGX seal key changed.
