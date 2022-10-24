# Updating a manifest
In order to ensure the confidentiality of a deployed application, MarbleRun uses a manifest to define the software packages and the infrastructure your deployment uses. To verify that your deployment has not been altered, the manifest is usually set in stone after it was set to ensure no one can alter with your cluster.

Yet, updates play an important role to ensure your software stays secure. To avoid having to redeploy your application from scratch, MarbleRun allows uploading a separate "update manifest" which increases the minimum `SecurityVersion` of one or multiple already deployed packages. After such an update is performed, an old version of a defined software package cannot be loaded anymore under the current manifest.

## Requirements
In order to deploy an update, you need to be in possession of a certificate/private key pair belonging to a user from the `Users` section of the original manifest, as described in ["defining a manifest"](workflows/define-manifest.md#manifestmarbles).
Furthermore the user needs to be [permitted to update](workflows/define-manifest.md#manifestroles) the chosen packages.

If no user with the permission for updates has been initially set up, no updates can be applied.

## Defining an update manifest
The format of an update manifest follows the syntax of the original manifest, though it only expects to contain a package name and a new `SecurityVersion` value set for it.

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

If you now want to update the minimum required version for `frontend`, the complete definition for the update manifest just needs to be as short as this example:


```javascript
{
    "Packages": {
        "frontend": {
            "SecurityVersion": 5
        }
    }
}
```

Please do not define other values except the `SecurityVersion` value for a package, as MarbleRun will refuse to accept such an update manifest.

Also, if an update was already performed and you want to deploy another update on top of it, you can! Just make sure the `SecurityVersion` is indeed higher than defined in the previous update, as downgrades are not supported for security reasons.

## Deploying an update
Similar to other operations, an update can be deployed with the help of the CLI. Note that for this operation, you need to specify one of your defined `Users` certificates as a TLS client certificate, combined with the according private key.

This operation can be performed in the following way:

```bash
marblerun manifest update update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json
```

If everything went well, no message will be returned and your MarbleRun logs should highlight that an update manifest has been set. And if something went wrong, the API endpoint will return an error message telling you what happened. If you receive `unauthorized user` back, it means MarbleRun either received no client certificate over the TLS connection, or you used the wrong certificate.

## Effects of an update
When a manifest has been updated, the Coordinator will generate new certificates which your Marbles will receive upon the next startup. Also, if you are trying to launch Marbles based on packages containing the old `SecurityVersion`, they will refuse to run (unless you are running in SGX Simulation or non-Enclave mode). However, so far currently running Marbles will continue to run and will be able to authenticate each other, as long as they are still running, so if you need to enforce an update, make sure to kill the Marbles on your host and restart them.
