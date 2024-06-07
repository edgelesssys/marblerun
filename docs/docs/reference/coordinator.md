# Coordinator client API

The Coordinator exposes an HTTP-REST interface, referred to as the Client API.

Responses of the API follow the [JSend specification](https://github.com/omniti-labs/jsend).
This means all endpoints return a JSON object with a `status` field that's either "success", "fail", or "error":

* In case of "success", the response will contain a `data` field with the actual response data.
* In case of "error", the response will contain a `message` field with an error message.
* In case of "fail", the response may contain a `message` field with a human readable message, as well as a `data` field with additional information.
  * "fail" is only used in API version 2, and is returned on invalid requests by the client.

The Client API is used by the MarbleRun CLI and by [the MarbleRun Go SDK](https://pkg.go.dev/github.com/edgelesssys/marblerun/api) to interact with the Coordinator.
It may also be used directly by applications for programmatic access.

## Retrieve the Coordinator's manifest

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
GET /api/v2/manifest
```

Get the currently set manifest.

The endpoint returns a manifest signature as base64 encoded bytes (signed by the root ECDSA key) and a SHA-256 of the currently set manifest.
Further, the manifest itself is returned as base64 encoded bytes.
All returned values don't change when a package update has been applied.

Users can retrieve and inspect the manifest through this endpoint before interacting with the application.

Example for retrieving the deployed manifest with curl:

```bash
curl --cacert marblerun.crt "https://$MARBLERUN/api/v2/manifest" | jq '.data.ManifestSignature' --raw-output | base64 -d
```

### Returns

* `manifestSignatureRootECDSA` string

    Base64 encoded ECDSA signature of the manifest signed by the Coordinator's root key.

* `manifestFingerprint` string

    Hex encoded SHA-256 hash of the manifest.

* `manifest` string

    Base64 encoded manifest.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "manifestSignatureRootECDSA": "bWFuaWZlc3RTaWduYXR1cmVSb290RUNEU0E=",
        "manifestFingerprint": "c2fd772483c510d49a339ae207588642f46eb8f22537f77d6ac348691a41ba32",
        "manifest": "eyJQYWNrYWdlcyI6e30sIk1hcmJsZXMiOnt9fQo="
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
GET /manifest
```

Get the currently set manifest.

The endpoint returns a manifest signature as base64 encoded bytes (signed by the root ECDSA key) and a SHA-256 of the currently set manifest.
Further, the manifest itself is returned as base64 encoded bytes.
All returned values don't change when a package update has been applied.

Users can retrieve and inspect the manifest through this endpoint before interacting with the application.

Example for requesting the deployed manifest hash with curl:

```bash
curl --cacert marblerun.crt "https://$MARBLERUN/manifest" | jq '.data.ManifestSignature' --raw-output
```

Example for verifying the deployed manifest via the intermediate key signature:

```bash
# get manifest signature (signed by coordinator root key)
curl --cacert marblerun.crt "https://$MARBLERUN/manifest" | jq '.data.ManifestSignatureRootECDSA' --raw-output | base64 -d > manifest.sig
# extract root public key from coordinator certificate root
marblerun certificate root $MARBLERUN
openssl x509 -in marblerunRootCA.crt -pubkey -noout > root.pubkey
# verify signature
openssl dgst -sha256 -verify root.pubkey -signature manifest.sig manifest.json
# verification fails? try to remove newlines from manifest
awk 'NF {sub(/\r/, ""); printf "%s",$0;}' original.manifest.json  > formated.manifest.json
```

### Returns

* `manifestSignatureRootECDSA` string

    Base64 encoded ECDSA signature of the manifest signed by the Coordinator's root key.

* `manifestSignature` string

    Hex encoded SHA-256 hash of the manifest.

* `manifest` string

    Base64 encoded manifest.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "manifestSignatureRootECDSA": "bWFuaWZlc3RTaWduYXR1cmVSb290RUNEU0E=",
        "manifestSignature": "c2fd772483c510d49a339ae207588642f46eb8f22537f77d6ac348691a41ba32",
        "manifest": "eyJQYWNrYWdlcyI6e30sIk1hcmJsZXMiOnt9fQo="
    }
}
```

</TabItem>
</Tabs>

## Set the Coordinator's manifest

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
POST /api/v2/manifest
```

Before deploying applications to a MarbleRun deployment, a manifest needs to be set.
On success, a key-value mapping for encrypted secrets to be used for recovering the Coordinator in case of disaster recovery is returned.
The key matches each supplied key from RecoveryKeys in the Manifest.

### Request body

* `manifest` string

    Base64 encoded manifest.

Example request body:

```JSON
{
    "manifest": "eyJQYWNrYWdlcyI6e30sIk1hcmJsZXMiOnt9fQo="
}
```

### Returns

* `recoveryKeys` object

    An optional field that will be present if the manifest contains `RecoveryKeys`.
    Key-value mapping of strings to strings, where the key matches each supplied key from `RecoveryKeys` in the manifest,
    and the value is the base64 encoded encrypted recovery secret.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "recoveryKeys": {
            "recoveryKey1": "ZW5jcnlwdGVkUmVjb3ZlcnlTZWNyZXQxCg==",
            "recoveryKey2": "ZW5jcnlwdGVkUmVjb3ZlcnlTZWNyZXQyCg=="
        }
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
POST /manifest
```

Before deploying applications to a MarbleRun deployment, a manifest needs to be set.
On success, a key-value mapping for encrypted secrets to be used for recovering the Coordinator in case of disaster recovery is returned.
The key matches each supplied key from RecoveryKeys in the Manifest.

Example for setting the manifest with curl:

```bash
curl --cacert marblerun.crt --data-binary @manifest.json "https://$MARBLERUN/manifest"
```

### Request body

Raw JSON encoded manifest.
See [Defining a Manifest](../workflows/define-manifest.md) for more information.

Example request body:

```JSON
{
    "Packages": {
        "package1": {},
        "package2": {}
    },
    "Marbles": {
        "marble1": {},
        "marble2": {}
    },
    "Secrets": {},
    "Users": {},
    "Roles": {},
    "TLS": {},
    "RecoveryKeys": {
        "recoveryKey1": "-----BEGIN PUBLIC KEY-----\nMIIBpTANBgk...",
        "recoveryKey2": "-----BEGIN PUBLIC KEY-----\nMIIBpTANBgk..."
    }
}
```

### Returns

* `recoveryKeys` object

    An optional field that will be present if the manifest contains `RecoveryKeys`.
    Key-value mapping of strings to strings, where the key matches each supplied key from `RecoveryKeys` in the manifest,
    and the value is the base64 encoded encrypted recovery secret.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "recoveryKeys": {
            "recoveryKey1": "ZW5jcnlwdGVkUmVjb3ZlcnlTZWNyZXQxCg==",
            "recoveryKey2": "ZW5jcnlwdGVkUmVjb3ZlcnlTZWNyZXQyCg=="
        }
    }
}
```

</TabItem>
</Tabs>

## Retrieve the Coordinator's SGX quote and certificates

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
GET /api/v2/quote[?nonce=<base64_url_encoding(nonce)>]
```

Retrieves and SGX-DCAP quote from the Coordinator.
Learn more about DCAP in the [official Intel DCAP orientation](https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/docs/DCAP_ECDSA_Orientation.pdf).
This endpoint can be used to verify the integrity of the Coordinator and the cluster at any time.

### Query parameters

* `nonce` string (optional)

    Base64 URL encoded nonce to be included in the quote.

### Returns

* `cert` string

    PEM-encoded certificate chain containing the Coordinator's Root CA and Intermediate CA.
    Can be used for trust establishment between a client and the Coordinator.

* `quote` string

    Base64-encoded SGX quote where the report data is a SHA-256 hash of the Coordinator's root certificate complete ASN.1 DER content and the nonce, if provided:

    ```shell
    report_data = SHA256(coordinator_root_cert + nonce)
    ```

Example response:

```JSON
{
    "status": "success",
    "data": {
        "cert": "-----BEGIN CERTIFICATE-----\nMIIBpTANBgk...",
        "quote": "U0dYIHF1b3RlCg=="
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
GET /quote
```

Retrieves and SGX-DCAP quote from the Coordinator.
Learn more about DCAP in the [official Intel DCAP orientation](https://download.01.org/intel-sgx/sgx-dcap/1.21/linux/docs/DCAP_ECDSA_Orientation.pdf).
This endpoint can be used to verify the integrity of the Coordinator and the cluster at any time.

### Returns

* `cert` string

    PEM-encoded certificate chain containing the Coordinator's Root CA and Intermediate CA.
    Can be used for trust establishment between a client and the Coordinator.

* `quote` string

    Base64-encoded SGX quote where the report data is a SHA-256 hash of the Coordinator's root certificate complete ASN.1 DER content:

    ```shell
    report_data = SHA256(coordinator_root_cert)
    ```

Example response:

```JSON
{
    "status": "success",
    "data": {
        "cert": "-----BEGIN CERTIFICATE-----\nMIIBpTANBgk...",
        "quote": "U0dYIHF1b3RlCg=="
    }
}
```

</TabItem>
</Tabs>

## Recover the Coordinator

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
POST /api/v2/recover
```

Recover the Coordinator using decrypted recovery secrets.

This API endpoint is only available when the coordinator is in recovery mode.
Before you can use the endpoint, you need to decrypt the recovery secret which you may have received when setting the manifest initially.
See [Recovering the Coordinator](../workflows/recover-coordinator.md) on how to retrieve the recovery key needed to use this API endpoint correctly.

### Request body

* `recoverySecret` string

    Base64 encoded recovery secret.

### Returns

* `remaining` int

    Remaining secret shares to be uploaded for recovery to complete.

* `message` string

    A human readable message indicating the success or progress of the recovery process.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "remaining": 2,
        "message": "Secret was processed successfully. Upload the next secret. Remaining secrets: 2"
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
POST /recover
```

Recover the Coordinator using decrypted recovery secrets.

This API endpoint is only available when the coordinator is in recovery mode.
Before you can use the endpoint, you need to decrypt the recovery secret which you may have received when setting the manifest initially.
See [Recovering the Coordinator](../workflows/recover-coordinator.md) on how to retrieve the recovery key needed to use this API endpoint correctly.

Example for recovering the Coordinator with curl:

```bash
curl -k -X POST --data-binary @recovery_key_decrypted "https://$MARBLERUN/recover"
```

### Request body

Raw binary encoded recovery secret.

### Returns

* `statusMessage` string

    A human readable message indicating the success or progress of the recovery process.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "statusMessage": "Secret was processed successfully. Upload the next secret. Remaining secrets: 2"
    }
}
```

</TabItem>
</Tabs>

## Retrieve MarbleRun managed secrets

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
GET /api/v2/secrets?s=<secretName1>[&s=<secretName2>...]
```

Each requests allows specifying one or more secrets in the form of a query string, where each parameter `s` specifies one secret.
A query string for the secrets `symmetricKeyShared` and `certShared` may look like the following:

```http
s=symmetricKeyShared&s=certShared
```

This API endpoint only works when `Users` were defined in the manifest.
The user connects via mutual TLS using the user client certificate in the TLS Handshake.
For more information, look up [Managing secrets](../workflows/managing-secrets.md).

Example for retrieving the secrets `symmetricKeyShared` and `certShared`:

```bash
curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key "https://$MARBLERUN/secrets?s=symmetricKeyShared&s=certShared"
```

### Query parameters

* `s` string (required) one or more

    Secret name to retrieve.

### Returns

* `secrets` [object](#secret-object)

    Key-value mapping of strings to [secret objects](#secret-object), where the key matches each supplied secret name in the query string.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "secrets": {
            "symmetricKeyShared": {
                "type": "symmetric-key",
                "size": 128,
                "shared": true,
                "userDefined": false,
                "private": "QUFBQUFBQUFBQUFBQUFBQQ==",
                "public": "QUFBQUFBQUFBQUFBQUFBQQ==",
            },
            "certShared": {
                "type": "cert-ecdsa",
                "size": 256,
                "shared": true,
                "userDefined": false,
                "cert": "LS0tLS1CRU...",
            },
        },
    },
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
GET /secrets?s=<secretName1>[&s=<secretName2>...]
```

Each requests allows specifying one or more secrets in the form of a query string, where each parameter `s` specifies one secret.
A query string for the secrets `symmetricKeyShared` and `certShared` may look like the following:

```http
s=symmetricKeyShared&s=certShared
```

This API endpoint only works when `Users` were defined in the manifest.
The user connects via mutual TLS using the user client certificate in the TLS Handshake.
For more information, look up [Managing secrets](../workflows/managing-secrets.md).

Example for retrieving the secrets `symmetricKeyShared` and `certShared`:

```bash
curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key "https://$MARBLERUN/secrets?s=symmetricKeyShared&s=certShared"
```

### Query parameters

* `s` string (required) one or more

    Secret name to retrieve.

### Returns

Key-value mapping of strings to [secret objects](#secret-object), where the key matches each supplied secret name in the query string.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "symmetricKeyShared": {
            "type": "symmetric-key",
            "size": 128,
            "shared": true,
            "userDefined": false,
            "private": "QUFBQUFBQUFBQUFBQUFBQQ==",
            "public": "QUFBQUFBQUFBQUFBQUFBQQ==",
        },
        "certShared": {
            "type": "cert-ecdsa",
            "size": 256,
            "shared": true,
            "userDefined": false,
            "cert": "LS0tLS1CRU...",
        },
    },
}
```

</TabItem>
</Tabs>

### Secret object

* `type` string

    The type of the secret. One of "cert-ecdsa", "cert-ed25519", "cert-rsa", "symmetric-key", "plain".

* `size` integer

    Size of the key in bits.
    For Type "symmetric-key", this is a multiple of 8.
    For Type "cert-ecdsa", this maps to a curve supported by Go's crypto library, currently: 224, 256, 384, or 521.
    For "cert-ed25519", this is omitted.

* `shared` bool

    Specifies whether this secret is shared across all marbles, or if it is unique to each marble.

* `userDefined` bool

    Specifies whether a secret should be generated by the MarbleRun (false),
    or if it will be uploaded by a user at a later point (true).

* `cert` string

    Base64 encoded X.509 certificate.

* `validFor` int

    Validity of the certificate in days.

* `private` string

    Base64 encoded private key matching the certificate or symmetric key.

* `public` string

    Base64 encoded public key matching the certificate or symmetric key.

## Set secrets

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
POST /api/v2/secrets
```

This API endpoint only works when `Users` were defined in the manifest.
The user connects via mutual TLS using the user client certificate in the TLS Handshake.
For more information, look up [Managing secrets](../workflows/managing-secrets.md).

### Request body

* `secrets` object

    Key-value mapping of strings to [user secret objects](#user-secret-object), where the key is the name of the secret.

Example request body:

```JSON
{
    "secrets": {
        "symmetricKeyShared": {
            "key": "QUFBQUFBQUFBQUFBQUFBQQ==",
        },
        "certShared": {
            "cert": "LS0tLS1CRU...",
            "public": "LS0tLS1CRU...",
        },
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
POST /secrets
```

Setting secrets requires uploading them in JSON format.

This API endpoint only works when `Users` were defined in the manifest.
The user connects via mutual TLS using the user client certificate in the TLS Handshake.
For more information, look up [Managing secrets](../workflows/managing-secrets.md).

Example for setting secrets from the file `secrets.json`:

```bash
curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key --data-binary @secrets.json "https://$MARBLERUN/secrets"
```

### Request body

Key-value mapping of strings to [user secret objects](#user-secret-object), where the key is the name of the secret.

Example request body:

```JSON
{
    "symmetricKeyShared": {
        "key": "QUFBQUFBQUFBQUFBQUFBQQ==",
    },
    "certShared": {
        "cert": "LS0tLS1CRU...",
        "public": "LS0tLS1CRU...",
    },
}
```

</TabItem>
</Tabs>

### User secret object

* `key` string

    Base64 encoded symmetric-key or arbitrary base64 encoded data for secrets of type "plain".

* `cert` string

    Base64 encoded X.509 certificate.

* `public` string

    Base64 encoded public key matching the certificate.

Only `key` or `cert` and `public` may be set.

## Verify and sign an SGX quote

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
POST /api/v2/sign-quote
```

Send an SGX quote to the Coordinator for verification.
If the quote is valid, the Coordinator will sign the quote using its root ECDSA key, and return the signature with the TCB status of the quote.
The Coordinator does not verify if the quote matches any packages in the configured manifest.
The signature is created over the SHA-256 hash of the base64-encoded SGX quote and the TCB status:

```shell
signature = ECDSA_sign(root_priv_key, SHA256(base64(SGX_quote) + string(TCB_status)))
```

If the quote is invalid, the Coordinator will return a JSend fail response:

```JSON
{
    "status": "fail",
    "message": "quote verification failed: OE_QUOTE_VERIFICATION_ERROR",
}
```

### Request body

* `sgxQuote` string

    Base64 encoded SGX quote.

Example request body:

```JSON
{
    "sgxQuote": "U0dYIHF1b3RlCg=="
}
```

### Returns

* `signature` string

    Base64 encoded ECDSA signature of the SHA-256 hash of the base64-encoded SGX quote and the TCB status:

* `tcbStatus` string

    The TCB status of the SGX quote.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "signature": "RUNEU0Ffc2lnbihyb290X3ByaXZfa2V5LCBTSEEyNTYoYmFzZTY0KFNHWF9xdW90ZSkgKyBzdHJpbmcoVENCX3N0YXR1cykpKQo=",
        "tcbStatus": "UpToDate"
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

This API endpoint is not available in API version 1.

</TabItem>
</Tabs>

## Get the current status of the Coordinator

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
GET /api/v2/status
```

Get the current status of the Coordinator.

The status indicates the current state of the coordinator, and can be one of the following:

1. Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. Waiting for user input on [/recover](#recover-the-coordinator).
2. Coordinator is ready to accept a manifest on [/manifest](#set-the-coordinators-manifest).
3. Coordinator is running correctly and ready to accept marbles through the [Marble API](../workflows/add-service.md).

### Returns

* `status` int

    A status code that matches the internal code of the Coordinator's current state.

* `message` string

    A human readable message indicating the current state of the Coordinator.

</TabItem>
<TabItem value="v1" label="v1">

```http
GET /status
```

Get the current status of the Coordinator.

The status indicates the current state of the coordinator, and can be one of the following:

1. Coordinator is in recovery mode. Either upload a key to unseal the saved state, or set a new manifest. Waiting for user input on [/recover](#recover-the-coordinator).
2. Coordinator is ready to accept a manifest on [/manifest](#set-the-coordinators-manifest).
3. Coordinator is running correctly and ready to accept marbles through the [Marble API](../workflows/add-service.md).

### Returns

* `statusCode` int

    A status code that matches the internal code of the Coordinator's current state.

* `statusMessage` string

    A human readable message indicating the current state of the Coordinator.

</TabItem>
</Tabs>

## Get a log of all performed updates

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
GET /api/v2/update
```

Returns a structured log of all updates performed via the [`/update`](#update-the-manifest) or [`/secrets`](#set-secrets) endpoint, including timestamp, author, and affected resources.

### Returns

* `updateLog` array of strings

    A log of all performed updates.
    Each entry in the array is one JSON structured log entry.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "updateLog": [
            "{\"time\":\"2024-01-01T00:00:00.0\",\"update\":\"Initial manifest set\"}"
        ]
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
GET /update
```

Returns a structured log of all updates performed via the [`/update`](#update-the-manifest) or [`/secrets`](#set-secrets) endpoint, including timestamp, author, and affected resources.

### Returns

A string comprising the log of all performed updates.
The log is structured as a JSON array of objects, where each object is a log entry.

Example response:

```JSON
{
    "status": "success",
    "data": "{\"time\":\"2024-01-01T00:00:00.0\",\"update\":\"Initial manifest set\"}\n"}"
}
```

</TabItem>
</Tabs>

## Update the manifest

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
POST /api/v2/update
```

This API endpoint only works if `Users` are defined in the Manifest.
It requires uploading a manifest containing only the packages to be updated, or, if enabled, a completely new manifest.
The Coordinator will verify the manifest and return an error if the manifest is invalid.
For more information, have a look at [updating a Manifest](../workflows/update-manifest.md).

### Request body

For package updates:

* `manifest` string

    Base64 encoded manifest, containing only the packages to be updated, or, if enabled, a completely new manifest.

Example request body for package updates:

```JSON
{
    "manifest": "eyJQYWNrYWdlcyI6e30sIk1hcmJsZXMiOnt9fQo="
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
POST /update
```

This API endpoint only works if `Users` are defined in the Manifest.
It requires uploading a manifest containing only the packages to be updated, or, if enabled, a completely new manifest.
The Coordinator will verify the manifest and return an error if the manifest is invalid.
For more information, have a look at [updating a Manifest](../workflows/update-manifest.md).

Example for updating the manifest with curl:

```bash
curl --cacert marblerun.crt --cert user_certificate.crt --key user_private.key -w "%{http_code}" --data-binary @update_manifest.json "https://$MARBLERUN/update"
```

### Request body

For package updates:

* `packages` [object](#packages-object)

    Key-value mapping of strings to package objects, where the key is the name of the package to be updated.

Example request body for package updates:

```JSON
{
    "packages": {
        "package1": {
            "SecurityVersion": 4,
        },
        "package2": {
            "SecurityVersion": 3,
        }
    }
}
```

For full manifest updates the request body should contain the full manifest.
See [Defining a Manifest](../workflows/define-manifest.md) for more information.

### Packages object

* `SecurityVersion` int

    The new security version of the package.

</TabItem>
</Tabs>

## Acknowledge a pending manifest update

<EnterpriseBanner/>

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
POST /api/v2/update-manifest
```

If multiple users are allowed to perform full manifest updates, acknowledgement is required from all users before the manifest is applied.
See [multi-party updates](../workflows/update-manifest.md#acknowledging-a-multi-party-update) for more information.
Each user must upload the same manifest to acknowledge the update.

### Request body

* `manifest` string

    Base64 encoded manifest.

Example request body:

```JSON
{
    "manifest": "eyJQYWNrYWdlcyI6e30sIk1hcmJsZXMiOnt9fQo="
}
```

### Returns

* `message` string

    A human readable message indicating the success or progress of the update process.

* `missingUsers` array of strings

    An array of user IDs that have not yet acknowledged the update.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "message": "2 users still needs to acknowledge the update manifest.",
        "missingUsers": ["user1", "user2"]
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
POST /update-manifest
```

If multiple users are allowed to perform full manifest updates, acknowledgement is required from all users before the manifest is applied.
See [multi-party updates](../workflows/update-manifest.md#acknowledging-a-multi-party-update) for more information.
Each user must upload the same manifest to acknowledge the update.

### Request body

Raw JSON encoded manifest.

Example request body:

```JSON
{
    "Packages": {
        "package1": {},
        "package2": {}
    },
    "Marbles": {
        "marble1": {},
        "marble2": {}
    },
    "Secrets": {},
    "Users": {},
    "Roles": {},
    "TLS": {},
    "RecoveryKeys": {
        "recoveryKey1": "-----BEGIN PUBLIC KEY-----\nMIIBpTANBgk...",
        "recoveryKey2": "-----BEGIN PUBLIC KEY-----\nMIIBpTANBgk..."
    }
}
```

### Returns

* `message` string

    A human readable message indicating the success or progress of the update process.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "message": "2 users still needs to acknowledge the update manifest.",
    }
}
```

</TabItem>
</Tabs>

## View a pending manifest update

<EnterpriseBanner/>

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
GET /api/v2/update-manifest
```

Once a multi-party update has been initiated, users can view the pending manifest update.

### Returns

* `manifest` string

    Base64 encoded manifest.

* `missingUsers` array of strings

    An array of user IDs that have not yet acknowledged the update.

* `message` string

    A human readable message indicating the progress of the update process.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "manifest": "eyJQYWNrYWdlcyI6e30sIk1hcmJsZXMiOnt9fQo=",
        "missingUsers": ["user1", "user2"],
        "message": "2 users still needs to acknowledge the update manifest."
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
GET /update-manifest
```

Once a multi-party update has been initiated, users can view the pending manifest update.

### Returns

* `manifest` string

    Base64 encoded manifest.

* `missingUsers` array of strings

    An array of user IDs that have not yet acknowledged the update.

* `message` string

    A human readable message indicating the progress of the update process.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "manifest": "eyJQYWNrYWdlcyI6e30sIk1hcmJsZXMiOnt9fQo=",
        "missingUsers": ["user1", "user2"],
        "message": "2 users still needs to acknowledge the update manifest."
    }
}
```

</TabItem>
</Tabs>

## Cancel a pending manifest update

<EnterpriseBanner/>

<Tabs groupId="apiVersion">
<TabItem value="v2" label="v2">

```http
POST /api/v2/update-cancel
```

If a multi-party update has been initiated, users can cancel the pending manifest update.

### Returns

* `message` string

    A human readable message about the status of the update.

Example response:

```JSON
{
    "status": "success",
    "data": {
        "message": "Update successfully cancelled."
    }
}
```

</TabItem>
<TabItem value="v1" label="v1">

```http
POST /update-cancel
```

If a multi-party update has been initiated, users can cancel the pending manifest update.

### Returns

A human readable message about the status of the update.

Example response:

```JSON
{
    "status": "success",
    "data": "Update successfully cancelled."
}
```

</TabItem>
</Tabs>
