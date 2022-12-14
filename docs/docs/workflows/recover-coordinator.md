# Recovering the Coordinator

Different situations require the [recovery](../features/recovery.md) of the Coordinator.
If the Coordinator fails to unseal its state, it will enter recovery mode.

You need the corresponding private key to the [`RecoveryKeys` defined in the manifest](define-manifest.md#recoverykeys), and the [recovery secret returned to you during the initial upload of the manifest](set-manifest.md).

:::info

If you don't want or can't recover the old state, you can also dismiss it by [uploading a new manifest](set-manifest.md).
The old state will be overwritten on disk and the `/recover` endpoint won't be available anymore.

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

On success, the Coordinator applies the sealed state again. If the Coordinator can't restore the state with the uploaded key, an error will be returned in the logs and the `/recover` endpoint will stay open for further interaction.

## Multi-party recovery

<enterpriseBanner/>

If you've [configured your MarbleRun deployment for multi-party recovery](define-manifest.md#multi-party-recovery), send each party the corresponding [recovery secret](set-manifest.md). Ask them to perform the steps above. Once all parties have uploaded their secrets, the Coordinator recovers the sealed state and continues operation.
