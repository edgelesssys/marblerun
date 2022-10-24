# Recovering the Coordinator

As described in the [recovery chapter](features/recovery.md), different situations can require the *recovery* of the Coordinator.
If the Coordinator finds a sealed state during its startup which it is unable to unseal using the host-specific SGX sealing key, it will wait for further instructions.

!> You will need the corresponding private key to the `RecoveryKeys` which were defined in the manifest, and you will need the recovery secret that was returned to you during the initial upload of the manifest. If either or both of these are not available to you, recovery cannot be performed.

You have two options:

1. Recover the sealed state by uploading the recovery secret, which was encrypted for the `RecoveryKeys` defined in the manifest.

    The recovery secret can be uploaded through the `/recover` client API endpoint. To do so, you need to:

    * Get the temporary root certificate (valid only during recovery mode)
    * Decode the Base64 encoded output that was returned to you during the initial upload of the manifest
    * Decrypt the decoded output with the corresponding RSA private key of the key defined in the manifest
    * Upload the binary decoded and decrypted key to the `/recover` endpoint

    Assuming you saved the output from the manifest upload step in a file called `recovery_data` and the corresponding private key to the recovery key in a file called `private.pem`, perform recovery like this:

    ```bash
    base64 -d recovery_data \
    | openssl pkeyutl -inkey private.pem -decrypt \
        -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -out recovery_key_decrypted
    ```

    The extracted secret can then be uploaded using the MarbleRun CLI.

    ```bash
    marblerun recover recovery_key_decrypted $MARBLERUN
    ```

    Alternatively, you can use `curl`:
    ```bash
    era -c coordinator-era.json -h $MARBLERUN -output-root marblerun-temp.pem
    curl --cacert marblerun-temp.pem --data-binary @recovery_key_decrypted https://$MARBLERUN/recover
    ```

    If the recovery worked correctly, the Coordinator should apply the sealed state again without returning an error. In case the Coordinator was not able to restore the state with the uploaded key, an error will be returned in the logs and the `/recover` endpoint will stay open for further interaction.

2. Dismiss the sealed state by uploading a new manifest

    In case there is no desire to recover the old state it can simply be dismissed by [uploading a new manifest](workflows/set-manifest.md).

!> If a new manifest is uploaded, the old state will be overwritten on disk and the `/recover` endpoint will not be available anymore.
