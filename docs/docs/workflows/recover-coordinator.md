# Recovering the Coordinator

Different situations require the [recovery](../features/recovery.md) of the Coordinator.
If the Coordinator fails to unseal its state, it will enter recovery mode.

You need the corresponding private key to the [`RecoveryKeys` defined in the manifest](define-manifest.md#recoverykeys) and the [recovery secret returned to you during the initial upload of the manifest](set-manifest.md).

:::info

If you don't want or can't recover the old state, you can also dismiss it by [uploading a new manifest](set-manifest.md).
The old state will be overwritten on disk, and the `/recover` endpoint won't be available anymore.

:::

You can upload the recovery secret through the `/recover` client API endpoint. To do so, you need to:

* Decode the Base64-encoded output returned to you during the initial upload of the manifest
* Decrypt the decoded output with the corresponding RSA private key of the key defined in the manifest
* Get the temporary root certificate (valid only during recovery mode)
* Upload the decrypted key to the `/recover` endpoint

Assuming you saved the output from the manifest upload step in a file called `recovery_data` and the recovery private key in a file called `private_key.pem`, perform recovery like this:

```bash
base64 -d recovery_data \
  | openssl pkeyutl -inkey private_key.pem -decrypt \
    -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
    -out recovery_key_decrypted
```

You can then upload the extracted secret using the MarbleRun CLI:

```bash
marblerun recover recovery_key_decrypted $MARBLERUN
```

Alternatively, you can use `curl`:
```bash
era -c coordinator-era.json -h $MARBLERUN -output-root marblerun-temp.pem
curl --cacert marblerun-temp.pem --data-binary @recovery_key_decrypted https://$MARBLERUN/recover
```

On success, the Coordinator applies the sealed state again. If the Coordinator can't restore the state with the uploaded key, an error will be returned in the logs, and the `/recover` endpoint will stay open for further interaction.

## Multi-party recovery

<enterpriseBanner/>

If you've [configured your MarbleRun deployment for multi-party recovery](define-manifest.md#multi-party-recovery), send each party the corresponding [recovery secret](set-manifest.md). Ask them to perform the steps above. Once all parties have uploaded their secrets, the Coordinator recovers the sealed state and continues its operations.

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
    $ base64 -d recovery_data \
      | openssl pkeyutl -inkey private_key.pem -decrypt \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
        -out recovery_key_decrypted
    $ marblerun recover recovery_key_decrypted $MARBLERUN
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
    $ base64 -d recovery_data \
      | openssl pkeyutl -inkey private_key.pem -decrypt \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 \
        -out recovery_key_decrypted
    $ marblerun recover recovery_key_decrypted $MARBLERUN
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
