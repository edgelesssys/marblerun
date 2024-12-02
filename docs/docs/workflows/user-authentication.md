# User authentication

Some privileged workflows require a user to authenticate themselves to the MarbleRun Coordinator.
This is done by first [adding a user to the manifest](./define-manifest.md#users) and then using the certificate and matching private key as TLS client credentials when connecting to the Coordinator.

## File based authentication

With file based authentication, you need to have access to a private key and certificate as PEM formatted files.
For example, you can generate your credentials using the following `openssl` command:

```sh
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 -nodes -keyout admin_private.pem -out admin_certificate.pem
```

You can then use these files to authenticate with the MarbleRun Coordinator:

```sh
marblerun --cert admin_certificate.pem --key admin_private.pem [COMMAND]
```

## PKCS#11 based authentication

MarbleRun's CLI supports authentication with private keys stored in a PKCS#11 compatible device.
To load client credentials using PKCS#11, a [PKCS#11 config file](https://pkg.go.dev/github.com/ThalesGroup/crypto11@v1.2.6#Config) must be provided, which specifies how to access the PKCS#11 token.
Additionally, the ID and/or label of the private key and certificate must be provided to the CLI.

The PKCS#11 config file is a JSON file that should specify the following fields:

- `Path` (string) - The full path to the PKCS#11 shared library.
- `Pin` (string) - The PIN (password) to access the token.
- One of:
  - `TokenSerial` (string) - Serial number of the token to use.
  - `TokenLabel` (string) - Label of the token to use.
  - `SlotNumber` (int) - Number of the slot containing the token to use.

The following shows an example for authenticating with a key and certificate stored in a token with the label `marblerun-token`:

```json5
{
    "Path": "/usr/lib/softhsm/libsofthsm2.so", # Replace with path to your PKCS#11 shared library
    "TokenLabel": "marblerun-token",
    "Pin": "1234" # Replace with your token's actual password
}
```

Assuming the key and certificate have the label `marblerun-key` and `marblerun-cert` respectively, the CLI can be invoked as follows:

```sh
marblerun --pkcs11-config /path/to/pkcs11-config.json --pkcs11-key-label marblerun-key --pkcs11-cert-label marblerun-cert [COMMAND]
```
