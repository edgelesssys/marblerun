# Recovering the Coordinator

Different situations require the [recovery](../features/recovery.md) of the Coordinator.
If the Coordinator fails to unseal its state, it will enter recovery mode.

:::tip

Use [distributed Coordinator instances](../features/recovery.md#distributed-coordinator) to reduce the occurrence of events that require manual recovery.

:::

You need the corresponding private key to the [`RecoveryKeys` defined in the manifest](define-manifest.md#recoverykeys) and the [recovery secret returned to you during the initial upload of the manifest](set-manifest.md).

:::info

If you don't want or can't recover the old state, you can also dismiss it by [uploading a new manifest](set-manifest.md).
The old state will be overwritten on disk, and recovery won't be available anymore.

:::

To recover the Coordinator, you need to decode your recovery secret and upload it using the MarbleRun CLI.

Assuming you named your recovery key `recoverKey1` in the manifest, and you saved the output from the manifest upload step in a file called `recovery_data`, decode your secret with the following command:

```bash
jq -r '.RecoverySecrets.recoverKey1' recovery_data | openssl base64 -d > recovery_key_encrypted
```

Then decrypt and upload the extracted secret using the MarbleRun CLI:

```bash
marblerun recover recovery_key_encrypted $MARBLERUN --key private_key.pem
```

On success, the Coordinator applies the sealed state again. If the Coordinator can't restore the state with the uploaded key, an error will be returned in the logs, and the recovery endpoint will stay open for further interaction.

## Multi-party recovery

If you've [configured your MarbleRun deployment for multi-party recovery](define-manifest.md#multi-party-recovery), send each party the corresponding [recovery secret](set-manifest.md). Ask them to perform the steps above. Once all parties have uploaded their secrets, the Coordinator recovers the sealed state and continues its operations.

:::note

If your MarbleRun deployment uses [distributed Coordinator instances](../features/recovery.md#distributed-coordinator), make sure all parties send their secrets to the same Coordinator instance.
One way to achieve this is scaling the Coordinator to a single instance:

```bash
kubectl scale --replicas=1 -n marblerun deployment/marblerun-coordinator
```

After recovery, you can scale the Coordinator back to the desired number of instances.

:::

### Example

The following gives an example of a multi-party recovery workflow.

Assume the following `RecoveryKeys` were set in the manifest:

```javascript
    "RecoveryKeys": {
        "alice": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk/6gfFF+cbcTlj8MT+4M\njjpM+suTwNM9gjv47EAAQ==\n-----END PUBLIC KEY-----\n",
        "bob": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsnOEAvynVrbgLdp0lwcp\nk2k04+n4op6tp1Yw2OaDbEAAQ==\n-----END PUBLIC KEY-----\n"
    }
```

1. The Coordinator returned the following `RecoverySecrets`:

    ```shell-session
    $ marblerun manifest set manifest.json $MARBLERUN
    ...
    {"RecoverySecrets":{"alice":"EbkX/skIPrJISf8PiXdzRIKnwQyJ+VejtGzHGfES5NIPuCeEFedqgCVDk=","bob":"bvPzio4A4SvzeHajsb+dFDpDarErcU9wMR0V9hyHtG2lC4ZfyrYjDBE7wtis3eOPgDaMG/HCt="}}
    ```

2. Alice decrypts and uploads her recovery key using her private key `private_key.pem` as follows:

    ```shell-session
    $ marblerun status $MARBLERUN
    1: Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. For more information on how to proceed, consult the documentation.
    $ echo "EbkX/skIPrJISf8PiXdzRIKnwQyJ+VejtGzHGfES5NIPuCeEFedqgCVDk=" > recovery_data
    $ openssl base64 -d -in recovery_data > recovery_key_encrypted
    $ marblerun recover recovery_key_encrypted $MARBLERUN --key private_key.pem
    Successfully verified Coordinator, now uploading key
    Secret was processed successfully. Upload the next secret. Remaining secrets: 1
    ```

    The Coordinator log shows the following:

    ```json
    {"level":"info","ts":1674206799.524596,"caller":"clientapi/clientapi.go:234","msg":"Recover called"}
    {"level":"info","ts":1674206799.524596,"caller":"clientapi/clientapi.go:253","msg":"Recover: recovery incomplete, more keys needed","remaining":1}
    ```

3. Bob does the same with his key to complete the recovery procedure:

    ```shell-session
    $ marblerun status $MARBLERUN
    1: Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. For more information on how to proceed, consult the documentation.
    $ echo "bvPzio4A4SvzeHajsb+dFDpDarErcU9wMR0V9hyHtG2lC4ZfyrYjDBE7wtis3eOPgDaMG/HCt=" > recovery_data
    $ openssl base64 -d -in recovery_data > recovery_key_encrypted
    $ marblerun recover recovery_key_encrypted $MARBLERUN --key private_key.pem
    Successfully verified Coordinator, now uploading key
    Recovery successful.
    $ marblerun status $MARBLERUN
    3: Coordinator is running correctly and ready to accept marbles.
    ```

    The Coordinator log shows the following:

    ```json
    {"level":"info","ts":1674206836.5523517,"caller":"clientapi/clientapi.go:234","msg":"Recover called"}
    {"level":"info","ts":1674206836.5563517,"caller":"core/core.go:261","msg":"generating quote"}
    {"level":"info","ts":1674206836.6043515,"caller":"clientapi/clientapi.go:281","msg":"Recover successful"}
    ```

## Offline recovery secret signing

When recovering a Coordinator, the CLI decrypts and signs the secret with your private recovery key before sending it to the Coordinator over a TLS secured connection.
Depending on your deployment, it may not be acceptable to have your private key or the decrypted recovery secret on a machine connected to the internet.
For this case, MarbleRun provides the option to retrieve a public key from the Coordinator to encrypt your signed recovery secret on an air-gapped system.

The following gives an example of how to recover MarbleRun with your private recovery key on an air-gapped system.

Assume the following `RecoveryKeys` was set in the manifest:

```javascript
    "RecoveryKeys": {
        "alice": "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAk/6gfFF+cbcTlj8MT+4M\njjpM+suTwNM9gjv47EAAQ==\n-----END PUBLIC KEY-----\n"
    }
```

1. The Coordinator returned the following `RecoverySecrets`:

    ```shell-session
    $ marblerun manifest set manifest.json $MARBLERUN
    ...
    {"RecoverySecrets":{"alice":"EbkX/skIPrJISf8PiXdzRIKnwQyJ+VejtGzHGfES5NIPuCeEFedqgCVDk="}}
    ```

2. On a machine with access to the Coordinator, retrieve the Coordinator's recovery public key:

    ```shell-session
    $ marblerun status $MARBLERUN
    1: Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. For more information on how to proceed, consult the documentation.
    $ marblerun recover-with-signature public-key $MARBLERUN --output recovery-public.pem
    ```

    This will save the Coordinator's recovery public key to `recovery-public.pem`.

3. Move the recovery public key to the system with access to your private recovery key

4. Sign your recovery secret:

    ```shell-session
    echo "EbkX/skIPrJISf8PiXdzRIKnwQyJ+VejtGzHGfES5NIPuCeEFedqgCVDk=" > recovery_data
    openssl base64 -d -in recovery_data > recovery_key_encrypted
    marblerun recover-with-signature sign-secret recovery_key_encrypted --key private.pem --output recovery-secret.sig
    ```

5. Encrypt your recovery secret with the Coordinator's public key

    ```shell-session
    marblerun recover-with-signature encrypt-secret recovery_key_encrypted --coordinator-pub-key recovery-public.pem --key private.pem --output recovery-secret.enc
    ```

6. Move your encrypted recovery secret, `recovery-secret.enc`, and its matching signature, `recovery-secret.sig` back to a machine with access to the Coordinator

    ```shell-session
    marblerun recover-with-signature recovery-secret.enc $MARBLERUN --signature recovery-secret.sig
    ```
