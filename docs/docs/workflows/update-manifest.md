# Updating a manifest

When [defining the initial manifest](define-manifest.md), you have to choose whether it should be [partially or fully updatable](../features/manifest.md) by assigning appropriate [roles](define-manifest.md#roles) to eligible users.

## Package updates

Updates play an important role to ensure your software stays secure. To avoid having to redeploy your application from scratch, MarbleRun allows uploading a separate "update manifest" that increases the minimum `SecurityVersion` of already deployed packages. After such an update is performed, an old version of a defined software package can't be loaded anymore under the current manifest.

To deploy an update, your user needs to have a [role assigned that contains the `UpdateSecurityVersion` action](define-manifest.md#roles).

### Defining an update manifest
The format of an update manifest follows the syntax of the original manifest, but it only contains packages with new `SecurityVersion` values.

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

To deploy a new manifest, your user needs to have a [role assigned that contains the `UpdateManifest` action](define-manifest.md#roles).

## Deploying an update

Use the CLI to deploy an update, specifying the client certificate and private key of a user with appropriate permissions:

```bash
marblerun manifest update update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json
```

On success, no message will be returned and your MarbleRun logs should highlight that an update manifest has been set. On error, the API endpoint will return an error message. If you receive `unauthorized user`, MarbleRun either received no client certificate over the TLS connection, or you used the wrong certificate.

## Effects of an update
When a manifest has been updated, the Coordinator will generate new certificates which your Marbles will receive upon the next startup. Also, if you are trying to launch Marbles based on packages containing the old `SecurityVersion`, they will refuse to run (unless you are running in SGX Simulation or non-Enclave mode). However, so far currently running Marbles will continue to run and will be able to authenticate each other, as long as they're still running. So if you need to enforce an update, make sure to kill the Marbles on your host and restart them.
