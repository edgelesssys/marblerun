# Updating a manifest

When [defining the initial manifest](define-manifest.md), you have to choose whether it should be [partially or fully updatable](../features/manifest.md) by assigning appropriate [roles](define-manifest.md#roles) to eligible users.

## Package updates

Updates play an important role in ensuring your software stays secure. To avoid redeploying your application from scratch, MarbleRun allows uploading a separate "update manifest" that increases the minimum `SecurityVersion` of already deployed packages. After such an update is performed, an old version of a defined software package can't be loaded anymore under the current manifest.

To deploy an update, your user needs to have a [role assigned that contains the `UpdateSecurityVersion` action](define-manifest.md#roles).

### Defining an update manifest
The update manifest format follows the original manifest's syntax, but it only contains packages with new `SecurityVersion` values.

For example, the current `Packages` section of your original manifest looks like this:

```javascript
{
    // ...
    "Packages": {
        "backend": {
            "UniqueID": "6b2822ac2585040d4b9397675d54977a71ef292ab5b3c0a6acceca26074ae585",
            "Debug": false
        },
        "frontend": {
            "SignerID": "43361affedeb75affee9baec7e054a5e14883213e5a121b67d74a0e12e9d2b7a",
            "ProductID": 43,
            "SecurityVersion": 3,
            "Debug": true
        }
    }
    // ...
}
```

To update the minimum required version for `frontend`, the complete definition for the update manifest just needs to be:

```javascript
{
    "Packages": {
        "frontend": {
            "SecurityVersion": 5
        }
    }
}
```

Don't define other values except the `SecurityVersion` value for a package, as MarbleRun refuses to accept such an update manifest.

## Full update

<enterpriseBanner/>

Some deployment scenarios require more flexibility regarding changes to the manifest. To this end, MarbleRun also allows uploading a full manifest. User-defined secrets and secrets of type `symmetric-key` are retained if their definition doesn't change.

To deploy a new manifest, your user must have a [role assigned that contains the `UpdateManifest` action](define-manifest.md#roles).
If multiple users have such a role assigned, each of them must [acknowledge](#acknowledging-a-multi-party-update) the new manifest.

## Deploying an update

Use the CLI to deploy an update, specifying the client certificate and private key of a user with appropriate permissions:

```bash
marblerun manifest update apply update-manifest.json $MARBLERUN --cert=user-cert.pem --key=user-key.pem
```

On success, no message will be returned and your MarbleRun logs should highlight whether the update manifest has been set or further acknowledgements are required. On error, the API endpoint will return an error message. If you receive `unauthorized user`, MarbleRun either received no client certificate over the TLS connection, or you used the wrong certificate.

## Acknowledging a multi-party update

All users that have the `UpdateManifest` permission are required to acknowledge a full manifest update.
To this end, they need to upload the same manifest.
This proves that they have knowledge of and agree on this manifest.

Use the CLI to acknowledge the update:

```bash
marblerun manifest update acknowledge update-manifest.json $MARBLERUN --cert=user-cert.pem --key=user-key.pem
```

See the [CLI reference](../reference/cli.md#marblerun-manifest-update) for further operations like getting the deployed update manifest or canceling the update procedure.

## Example: Multi-party update

The following gives an example of a full manifest update with multiple parties.

Assume the following `Users` and `Roles` were defined in the manifest:

```javascript
    "Users": {
        "alice": {
            "Certificate": "-----BEGIN CERTIFICATE-----\nMIIFZTCCA02gAwIBAgIUANHwS8RM0PUDl9htA+yWJx9WqucwDQYJKoZIhvcNAQEL\nBQAwQjELMAkGA1UEBhMC=\n-----END CERTIFICATE-----\n",
            "Roles": [
                "UpdateManifest"
            ]
        },
        "bob": {
            "Certificate": "-----BEGIN CERTIFICATE-----\nMIIFZTCCA02gAwIBAgIUJvtF7KRsunTmWVtpU9198HUxyLEwDQYJKoZIhvcNAQEL\nBQAwQjELMAkGA1UEBhMC=\n-----END CERTIFICATE-----\n",
            "Roles": [
                "UpdateManifest"
            ]
        }
    },
    "Roles": {
        "UpdateManifest": {
            "ResourceType": "Manifest",
            "Actions": ["UpdateManifest"]
        }
    }
```

1. Alice applies an update by uploading an update manifest:

    ```shell-session
    $ marblerun manifest update apply new_manifest.json $MARBLERUN --cert alice.crt --key alice-private.pem
    Coordinator verified
    Successfully verified Coordinator, now uploading manifest
    Update manifest set successfully
    ```

    The Coordinator log shows the following:

    ```json
    {"level":"info","ts":1674205619.1967707,"caller":"clientapi/clientapi.go:199","msg":"UpdateManifest called"}
    {"level":"info","ts":1674205619.2007706,"caller":"clientapi/clientapi.go:282","msg":"UpdateManifest successful. Waiting for acknowledgments to apply the update","missingAcknowledgments":1}
    ```

2. Bob checks the planned update:

    ```shell-session
    $ marblerun manifest update get $MARBLERUN
    Successfully verified Coordinator
    {
        "Marbles": {
        ...
    }
    ```

3. Finally, Bob acknowledges the update by providing the updated manifest again. Alice can either distribute the update manifest to Bob via a second channel, or Bob uses the manifest obtained from `marblerun manifest update get`:

    ```shell-session
    $ marblerun manifest update acknowledge new_manifest.json $MARBLERUN --cert bob.crt --key bob-private.pem
    Coordinator verified
    Successfully verified Coordinator
    Acknowledgement successful: All users have acknowledged the update manifest. Update successfully applied
    ```

    The Coordinator log shows the following:

    ```json
    {"level":"info","ts":1674205860.3970933,"caller":"clientapi/update.go:67","msg":"Received update acknowledgement","user":"bob","missingAcknowledgments":0}
    {"level":"info","ts":1674205860.3970933,"caller":"clientapi/update.go:72","msg":"All users have acknowledged the update manifest, applying update"}
    ...
    {"level":"info","ts":1674205321.4204075,"caller":"clientapi/update.go:176","msg":"An updated manifest overriding the original manifest was set."}
    {"level":"info","ts":1674205321.4204075,"caller":"clientapi/update.go:177","msg":"Please restart your Marbles to enforce the update."}
    {"level":"info","ts":1674205321.4204075,"caller":"clientapi/update.go:183","msg":"UpdateManifest successful"}
    ```

4. Alternatively, Alice or Bob may decide to cancel the update procedure instead:

    ```shell-session
    $ marblerun manifest update cancel $MARBLERUN --cert bob.crt --key bob-private.pem
    Coordinator verified
    Loading client certificate
    Creating client
    Successfully verified Coordinator
    Cancellation successful
    ```

    The Coordinator log shows the following:

    ```json
    {"level":"info","ts":1674205264.1442728,"caller":"clientapi/update.go:223","msg":"Manifest update canceled","user":"bob"}
    ```

## Effects of an update
When a manifest has been updated, the Coordinator will generate new certificates which your Marbles will receive upon the next startup. Also, if you are trying to launch Marbles based on packages containing the old `SecurityVersion`, they will refuse to run (unless you are running in SGX Simulation or non-Enclave mode). However, so far currently running Marbles will continue to run and will be able to authenticate each other, as long as they're still running. So if you need to enforce an update, make sure to kill the Marbles on your host and restart them.
