# Defining a manifest

The manifest is a simple JSON file that determines the key properties of your cluster: [`Packages`](#packages), [`Marbles`](#marbles), [`Secrets`](#secrets), [`Users`](#users), [`Roles`](#roles), [`RecoveryKeys`](#recoverykeys), and [`TLS`](#tls).
This article describes how to define these in your `manifest.json`.

For a working example see the manifest of the [emojivoto demo](https://github.com/edgelesssys/emojivoto/blob/main/tools/manifest.json). See also the [sample and template manifests](https://github.com/edgelesssys/marblerun/tree/master/samples).

## Packages

The `Packages` section of the manifest lists all the secure enclave software packages that your application uses. A package is defined by the following properties.

* `UniqueID`: this value will pin this package to one specific release build of an application. It represents the globally unique ID of the enclave software package; on SGX, this corresponds to the `MRENCLAVE` value, which is the SHA-256 hash of the enclave's initial contents and its configuration.
* `SignerID`: this value limits MarbleRun to only accept releases signed by a given public key. On SGX, this corresponds to the `MRSIGNER` value, which is the SHA-256 hash of the enclave issuer's RSA-3072 public key.
* `ProductID`: an integer that uniquely identifies the enclave software for a given `SignerID`. Can only be used in conjunction with `SignerID`.
* `SecurityVersion`: an integer that reflects the security-patch level of the enclave software. Can only be used in conjunction with `SignerID`.
* `Debug`: set to `true` if the enclave is to be run in debug mode. This allows you to experiment with deploying your application with MarbleRun without having to worry about setting correct values for the above properties, but note that enclaves in debug mode aren't secure.
* `AcceptedTCBStatuses`: a list of acceptable TCB statuses a Marble is allowed to start with. You can use this option to allow Marbles to run on machines whose TCB is out-of-date.

The following gives an example of a simple `Packages` section with made-up values.

```javascript
{
    // ...
    "Packages": {
        "backend": {
            "UniqueID": "6b2822ac2585040d4b9397675d54977a71ef292ab5b3c0a6acceca26074ae585",
            "Debug": false,
            "AcceptedTCBStatuses": [
                "ConfigurationNeeded",
                "ConfigurationAndSWHardeningNeeded"
            ]
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

In this example, `backend` is identified through `UniqueID`. Since `UniqueID` is the hash of the enclave software package, this means that `backend` can't be updated. (That' s because any update to the package will change the hash.)

In contrast, `frontend` is identified through the triplet `SignerID`, `ProductID`, and `SecurityVersion`. `SignerID` cryptographically identifies the vendor of the package; `ProductID` is an arbitrary product ID chosen by the vendor, and `SecurityVersion` is the security-patch level of the product. See our [adding a service hands-on](../workflows/add-service.md#step-21-define-the-enclave-software-package) on how to get these values for a given service.

## Marbles

Marbles represent the actual services in your mesh. They're defined in the `Marbles` section, which typically looks somewhat like the following example.

```javascript
{
    // ...
    "Marbles": {
        "backendFirst": {
            "Package": "backend",
            "MaxActivations": 1,
            "Parameters": {
                "Files": {
                    "/tmp/defg.txt": "foo",
                    "/tmp/jkl.mno": "bar",
                    "/tmp/pqr.ust": {
                        "Data": "Zm9vCmJhcg==",
                        "Encoding": "base64",
                        "NoTemplates": true
                    }
                },
                "Env": {
                    "IS_FIRST": "true",
                    "ROOT_CA": "{{ pem .MarbleRun.RootCA.Cert }}",
                    "MARBLE_CERT": "{{ pem .MarbleRun.MarbleCert.Cert }}",
                    "MARBLE_KEY": "{{ pem .MarbleRun.MarbleCert.Private }}"
                },
                "Argv": [
                    "--first",
                    "serve"
                ]
            },
            "TLS": [
                "backendFirstTLS"
            ]
        },
        "frontend": {
            "Package": "frontend",
            "Parameters": {
                "Env": {
                    "ROOT_CA": "{{ pem .MarbleRun.RootCA.Cert }}",
                    "MARBLE_CERT": "{{ pem .MarbleRun.MarbleCert.Cert }}",
                    "MARBLE_KEY": "{{ pem .MarbleRun.MarbleCert.Private }}"
                }
            },
            "TLS": [
                "frontendTLS1", "frontendTLS2"
            ]
        }
    }
    //...
}
```

Each Marble corresponds to a [`Package`](#packages) and defines a set of optional [`TLS` Tags](#tls) and `Parameters`:

* `Files`: Files and their contents
* `Env`: Environment variables
* `Argv`: Command line arguments

### Files and Env
Entries for these types can be defined in two ways:
* By using a direct mapping of filename to content: `"<FileName>": "<Content>"`
* By specifying an encoding for the content, and optionally, if the content contains templates:
    ```javascript
    "<FileName>": {
        "Data": "<Content>",
        "Encoding": "<EncodingType>",
        "NoTemplates": true/false
    }
    ```
    * `Data`: The file content
    * `Encoding`: Allows users to encode the `Data` field of the manifest. Marbles receive the decoded value. The following options are available:
        * `string`: No encoding. This is the default
        * `base64`: The manifest contains `Data` in [Base64](https://pkg.go.dev/encoding/base64). This can be useful to set content that can otherwise not be parsed in JSON format, or to avoid having to worry about correctly escaping newlines in a multi-line document
        * `hex`: Same as `base64`, but [Hex Encoding](https://pkg.go.dev/encoding/hex) is used instead
    * `NoTemplates`: If this flag is set, content in `Data` isn't processed for templates. Use this if your file contains [Go Templates](https://golang.org/pkg/text/template/) structures that shouldn't be interpreted by MarbleRun.

### Argv
Command line arguments are defined as an array. Entries are passed to the Marble in order, with the first being `argv[0]`.
Usually, `argv[0]` is expected to be the name of the executable.
Templates aren't supported.

The general format is the following:
```javascript
"Argv": [
    "<AppName>"
    "<FirstArg>"
    "<SecondArg>"
    //...
    "<LastArg>"
]
```

### Templates

`Parameters` are passed from the Coordinator to secure enclaves (i.e., Marbles) after successful initial remote attestation. In the remote attestation step, the Coordinator ensures that enclaves run the software defined in the `Packages` section. It's important to note that `Parameters` are only accessible from within the corresponding secure enclave. `Parameters` may contain arbitrary static data. However, they can also be used to securely communicate different types of dynamically generated cryptographic keys and certificates to Marbles. For this, we use [Go Templates](https://golang.org/pkg/text/template/) with the following syntax.

`{{ <encoding> <name of secret> }}`

The following encoding types are available to both `Files` and `Env`:

* `hex`: hex string
* `base64`: Base64 encoding
* `pem`: PEM encoding with a header matching the type of the requested key or certificate


The following encoding types are only available to `Files`:

* `raw`: raw bytes

The following encoding types are only available to `Env`:

* `string`: similar to `raw`, but doesn't allow [NULL bytes](https://man7.org/linux/man-pages/man7/environ.7.html). Since the content in non-user-defined secrets is random, and can't be controlled, only secrets with `UserDefined` set to `true` are allowed to use this encoding.

The following named keys and certificates are always available.

* `.MarbleRun.RootCA.Cert`: the root certificate of the cluster issued by the Coordinator; this can be used to verify the certificates of all Marbles in the cluster.
* `.MarbleRun.MarbleCert.Cert`: the Marble's certificate; this is issued by the `.MarbleRun.RootCA.Cert` and is for Marble-to-Marble and Marble-to-client authentication.
* `.MarbleRun.MarbleCert.Private`: the Marble's private key corresponding to `.MarbleRun.MarbleCert.Cert`

Finally, the optional field `MaxActivations` can be used to restrict the number of distinct instances that can be created of a Marble.

## Secrets

In the [previous section](#marbles), we discussed how certain cryptographic keys and certificates can be injected into a Marble's `Parameters` using Go Templates. In addition, MarbleRun also allows for the specification of custom cryptographic keys and certificates in the `Secrets` section. A typical `Secrets` section looks like the following.

```javascript
{
    //...
    "Secrets": {
        "secretAESKey": {
            "Type": "symmetric-key",
            "Size": 128,
            "Shared": true
        },
        "rsaCert": {
            "Type": "cert-rsa",
            "Size": 2048,
            "Shared": false,
            "ValidFor": 7,
            "Cert": {
                "Subject": {
                    "CommonName": "MarbleRun Unit Test"
                }
            }
        },
        "secretKeyUnset": {
            "Type": "symmetric-key",
            "Size": 128,
            "UserDefined": true
        }
    }
    //...
}
```

When defining a custom key or certificate, the following fields are available.

* `Type`: can be either `symmetric-key` for a symmetric encryption key, `cert-rsa`, `cert-ecdsa`, `cert-ed25519` or `plain`. Secrets of type `plain` contain arbitrary data uploaded by users, and are never generated by the Coordinator.
* `Size`: the size of the key in bits. For symmetric keys, this needs to be a multiple of `8`. For ECDSA, this needs to map to a curve supported by Go's `crypto` library, currently: `224`, `256`, `384`, or `521`. For Ed25519, this should be omitted.
* `Shared` (default: `false`): specifies if the secret should be shared across all Marbles (`true`), or if the secret should be uniquely generated for each Marble (`false`). See [Secrets management](../features/secrets-management.md) for more info.
* `ValidFor` (only for certificates, default: `365`): validity of the certificate in days; can't be specified in combination with the `NotAfter`.
* `Cert` (only for certificates): allows for the specification of additional X.509 certificate properties. See below for details.
* `UserDefined` (default: `false`): specifies if the secret should be generated by MarbleRun (`false`), or if it will be [uploaded by a user](../workflows/managing-secrets.md) later (`true`).

### Available `Cert` fields

When specifying a custom certificate in the `Secrets` section, the following properties can be set. These map directly to Go's  `x509.Certificate` structure. (This is because the Coordinator is written in Go.)

```javascript
"Cert": {
        "SignatureAlgorithm": 0,
        "Subject": {
            "Country": null,
            "Organization": null,
            "OrganizationalUnit": null,
            "Locality": null,
            "Province": null,
            "StreetAddress": null,
            "PostalCode": null,
            "CommonName": "",
            "Names": null,
            "ExtraNames": null
        },
        "NotAfter": "0001-01-01T00:00:00Z",
        "KeyUsage": 0,
        "ExtKeyUsage": null,
        "UnknownExtKeyUsage": null,
        "MaxPathLen": 0,
        "MaxPathLenZero": false,
        "SubjectKeyId": null,
        "AuthorityKeyId": null,
        "OCSPServer": null,
        "IssuingCertificateURL": null,
        "DNSNames": null,
        "EmailAddresses": null,
        "IPAddresses": null,
        "URIs": null,
        "PermittedDNSDomainsCritical": false,
        "PermittedDNSDomains": null,
        "ExcludedDNSDomains": null,
        "PermittedIPRanges": null,
        "ExcludedIPRanges": null,
        "PermittedEmailAddresses": null,
        "ExcludedEmailAddresses": null,
        "PermittedURIDomains": null,
        "ExcludedURIDomains": null,
        "CRLDistributionPoints": null,
        "PolicyIdentifiers": null
    }
```
Typically, you only define a subset of these. Commonly used properties include for example:
* `DNSNames`
* `IPAdresses`
* `KeyUsage` & `ExtKeyUsage`
* `Subject` (+ children)

The following X.509 properties can't be specified because they're set by the Coordinator when creating a certificate.
* `Issuer`: always set to "MarbleRun Coordinator"
* `SerialNumber`: always set to a unique, random value
* `BasicConstraintsValid`: always set to "true"
* `NotBefore`: always set to the host time at creation

### Injecting custom secrets

Keys and certificates defined in the `Secrets` section can be injected via `Parameters` using the following syntax.

`{{ <encoding> .Secrets.<name>.<part> }}`

Refer to the [previous section](#marbles) for a list of supported encodings. `<part>` can be any of the following.

* *empty*: for secret type `symmetric-key`, returns the symmetric key. For secret type `plain`, returns the secret data. For other types, returns the public key.
* `Cert`: returns the certificate.
* `Public`: returns the public key.
* `Private`: returns the private key.

The following gives some examples.

* Inject the certificate of custom secret `rsaCert` in PEM format: `{{ pem .Secrets.rsaCert.Cert }}`
* Inject the corresponding private key in PKCS#8 format: `{{ raw .Secrets.rsaCert.Private }}`
* Inject the corresponding public key PKIX-encoded and in PEM format: `{{ pem .Secrets.rsaCert.Public }}`
* Inject a symmetric key in hex format: `{{ hex .Secrets.secretAESKey }}`

## Users
The optional entry `Users` defines user credentials and role bindings for authentication and access control.
Each user is authenticated via a client certificate. The certificate needs to be specified as a PEM-encoded self-signed X.509 certificate.
Users with the appropriate roles can [update a manifest](../workflows/update-manifest.md) and [read or write secrets](../workflows/managing-secrets.md).

```javascript
{
    //...
    "Users": {
        "alice": {
            "Certificate": "-----BEGIN CERTIFICATE-----\nMIIFPjCCA...",
            "Roles": [
                "secretManager",
                "updateFrontend"
            ]
        },
        "bob": {
            "Certificate": "-----BEGIN CERTIFICATE-----\nMIIFP...",
            "Roles": [
                "secretManager",
                "updateBackend"
            ]
        }
    }
    //...
}
```
When verifying certificates in this context, MarbleRun ignores their `issuer`, `subject`, and `expiration date` fields. Thus, users can't lock themselves out through expired certificates.

Use OpenSSL to generate a compatible certificate.

```bash
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout admin_private.key -out admin_certificate.crt
```

Use the following command to preserve newlines correctly:

```bash
awk 'NF {sub(/\r/, ""); printf "%s\\n",$0;}' admin_certificate.pem
```
## Roles

MarbleRun supports Role-based access control (RBAC).
An RBAC Role represents a set of permissions for a MarbleRun `User`. Permissions are purely additive (there are no "deny" rules).
Each role defines a `ResourceType` (one of `Packages` or `Secrets`), a list of `ResourceNames` of that type, and a list of `Actions` that role permits on the listed resources.

Valid `Actions` are:
* For `"ResourceType": "Secrets"`: `ReadSecret` and `WriteSecret`, allowing reading and writing a secret respectively
* For `"ResourceType": "Packages"`: `UpdateSecurityVersion`, allowing to update the `SecurityVersion` of a given package
* For `"ResourceType": "Manifest"`: `UpdateManifest`, allowing to update the full manifest (MarbleRun Enterprise only)

:::note

Assigning a role with the `UpdateManifest` action to multiple users enables [multi-party manifest update](../features/manifest.md#multi-party-update): each of the users can upload a manifest, but all other users must [acknowledge this manifest](update-manifest.md#acknowledging-a-multi-party-update).

:::

```javascript
{
    //...
    "Roles": {
        "updateFrontend": {
            "ResourceType": "Packages",
            "ResourceNames": ["frontend"],
            "Actions": ["UpdateSecurityVersion"]
        },
        "updateBackend": {
            "ResourceType": "Packages",
            "ResourceNames": ["backend"],
            "Actions": ["UpdateSecurityVersion"]
        },
        "secretManager": {
            "ResourceType": "Secrets",
            "ResourceNames": [
                "secretKeyUnset",
                "genericSecret"
            ],
            "Actions": [
                "ReadSecret",
                "WriteSecret"
            ]
        },
        "updateManifest": {
            "ResourceType": "Manifest",
            "Actions": ["UpdateManifest"]
        }
    }
    //...
}
```

:::note

Deployment updates will only be possible if you create a role with permissions to update the particular packages and bind a user to that role.
The same applies for setting user-defined secrets.

:::

## RecoveryKeys

The optional entry `RecoveryKeys` holds PEM-encoded RSA public keys that can be used to [recover](../features/recovery.md) a failed MarbleRun deployment.

```javascript
{
    //...
    "RecoveryKeys":
    {
        "recoveryKey1": "-----BEGIN PUBLIC KEY-----\nMIIBpTANBgk..."
    }
    //...
}
```

You can generate this key with OpenSSL:

```bash
openssl genrsa -out private_key.pem 4096
openssl rsa -in private_key.pem -pubout -out public_key.pem
```

Use the following command to preserve newlines correctly:

```bash
awk 1 ORS='\\n' public_key.pem
```

### Multi-party recovery

<enterpriseBanner/>

To enable [multi-party recovery](../features/recovery.md#multi-party-recovery), first ask the other parties to generate key pairs as described above and receive their public keys via an authenticated channel.

Add all public keys to the manifest:

```javascript
{
    //...
    "RecoveryKeys":
    {
        "admin": "-----BEGIN PUBLIC KEY-----\n...",
        "dataProtectionOfficer": "-----BEGIN PUBLIC KEY-----\n...",
        "collaborator": "-----BEGIN PUBLIC KEY-----\n..."
    }
    //...
}
```

## TLS

:::note

The Transparent TLS feature is currently only available for EGo and Edgeless RT Marbles. Gramine and Occlum aren't supported yet.

:::

The TLS entry holds a list of tags which can be used in a Marble's definition. Each tag can define multiple `Incoming` and `Outgoing` connections. To elevate the connection between two marbles to TLS, the client needs to set the server under `Outgoing` and the server needs to define its service under `Incoming`.

Outgoing connections are defined by `Port` and `Addr`. For `Addr`, you can use both IP addresses and domains, e.g., the DNS names of other services.

Incoming connections are defined by `Port`. For services used by external clients, you must disable client authentication by setting `DisableClientAuth` to `true` and set `Cert`. Use the name of a certificate defined in the [Secrets section](#secrets).

```javascript
{
    //...
    "TLS":
    {
        "frontendTLS1": {
            "Outgoing": [
                {
                    "Port": "8080",
                    "Addr": "service.name"
                },
                {
                    "Port": "4443",
                    "Addr": "10.111.37.164"
                }
            ],
            "Incoming": [
                {
                    "Port": "8443"
                },
                {
                    "Port": "8080",
                    "Cert": "rsaCert",
                    "DisableClientAuth": true
                }
            ]
        },
        "backendFirstTLS": {
            // ...
        }
    }
}
```
