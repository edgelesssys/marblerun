# Building a service: Gramine

Running a Gramine app with MarbleRun requires some changes to its manifest. These are explained in the following. See also the [hello world example](https://github.com/edgelesssys/marblerun/tree/master/samples/gramine-hello) for a simple introduction, or the [nginx](https://github.com/edgelesssys/marblerun/tree/master/samples/gramine-nginx) and [Redis](https://github.com/edgelesssys/marblerun/tree/master/samples/gramine-redis) examples for more detailed applications.

## Requirements

First, get Gramine up and running. Gramine is available [as a Debian package](https://github.com/gramineproject/gramine/releases). Alternatively you can follow either the [Building](https://gramine.readthedocs.io/en/latest/devel/building.html) or [Cloud Deployment](https://gramine.readthedocs.io/en/latest/cloud-deployment.html) guide to build and install Gramine from source.

Before running your application, make sure you got the prerequisites for ECDSA remote attestation installed on your system. You can collectively install them with the following command:

```sh
sudo apt install libsgx-quote-ex-dev
```

## Configuration

### Entrypoint and argv

We provide the `premain-libos` executable with the [MarbleRun Releases](https://github.com/edgelesssys/marblerun/releases). It will contact the Coordinator, set up the environment, and run the actual application.

Set the premain executable as [the entry point](https://gramine.readthedocs.io/en/v1.3/manifest-syntax.html#libos-entrypoint) of the Gramine application and place the actual entry point [in argv0](https://gramine.readthedocs.io/en/v1.3/manifest-syntax.html#command-line-arguments):

```toml
libos.entrypoint = "file:premain-libos"

# argv0 needs to contain the name of your executable
loader.argv = ["hello"]

# add the premain to the list of trusted files
sgx.trusted_files = [
    # ...
    "file:premain-libos"
]
```

After the premain is done running, it will automatically spawn your application.

### Host environment variables

By default, environment variables from the host won't be passed to the application.
Gramine allows to [pass through whitelisted environment variables from the host](https://gramine.readthedocs.io/en/v1.3/manifest-syntax.html#environment-variables).
The premain needs access to the following [environment variables for configuration](../workflows/add-service.md#step-3-start-your-service):

```toml
loader.env.EDG_MARBLE_TYPE = { passthrough = true }
loader.env.EDG_MARBLE_COORDINATOR_ADDR = { passthrough = true }
loader.env.EDG_MARBLE_UUID_FILE = { passthrough = true }
loader.env.EDG_MARBLE_DNS_NAMES = { passthrough = true }
```

### UUID file

The Marble must be able to store its UUID:

```toml
sgx.allowed_files = [
    # ...
    "file:uuid"
]
```

### Remote attestation

The Marble will send an SGX quote to the Coordinator for remote attestation using [DCAP attestation](https://gramine.readthedocs.io/en/v1.3/manifest-syntax.html#attestation-and-quotes):

```toml
sgx.remote_attestation = "dcap"
```

### Enclave size and threads

The premain process is written in Go. The enclave needs to have enough resources for the Go runtime:

```toml
sgx.enclave_size = "1024M"
sgx.thread_num = 16
```

If your application has high memory demands, you may need to increase the size even further.

### Secret files

A Marble's secrets, e.g. a certificate and private key, can be provisioned as files. You can utilize Gramine's in-memory filesystem [`tmpfs`](https://gramine.readthedocs.io/en/latest/manifest-syntax.html#fs-mount-points), so the secrets will never show up on the host's file system :

```toml
fs.mounts = [
    # ...
    { type = "tmpfs", path = "/secrets" },
    # ...
]
```

You can specify the files' content in the MarbleRun manifest:

```javascript
...
    "Parameters": {
        "Files": {
            "/secrets/server.crt": "{{ pem .Secrets.serverCert.Cert }}",
            "/secrets/server.key": "{{ pem .Secrets.serverCert.Private }}"
        }
    }
...
```

Gramine also allows to store files [encrypted on the host's file system](https://gramine.readthedocs.io/en/v1.3/manifest-syntax.html#encrypted-files).

```toml
fs.mounts = [
  # ...
  { type = "encrypted", path = "/secrets", uri = "file:/path/to/local/directory", key_name = "[KEY_NAME]" },
  # ...
]
```

Gramine provides access to a pseudo filesystem for [setting the encryption key](https://gramine.readthedocs.io/en/v1.3/attestation.html#low-level-dev-attestation-interface).
MarbleRun can set up your enclave with keys at runtime by specifying them in the MarbleRun manifest:

```javascript
...
    "Parameters": {
        "Files": {
            "/dev/attestation/[KEY_NAME]": "{{ raw .Secrets.encryptedFilesKey }}"
        }
    }
...
```

You can see how this is done in the [nginx example](https://github.com/edgelesssys/marblerun/tree/master/samples/gramine-nginx).

## Troubleshooting

### aesm_service returned error: 30

If you receive the following error message on launch:

```sh
aesm_service returned error: 30
load_enclave() failed with error -1
```

Make sure you installed the Intel AESM ECDSA plugins on your machine. You can do this by installing the `libsgx-quote-dev` package mentioned in the requirements above.

If you are running your application in a container, you will need to mount the aesm socket. The socket is located at `/var/run/aesmd/`.

If you are deploying your application on Kubernetes with the [Intel SGX device plugin](https://intel.github.io/intel-device-plugins-for-kubernetes/cmd/sgx_plugin/README.html) installed, the socket is automatically mounted by setting the `sgx.intel.com/quote-provider: aesmd` annotation for your deployment:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: gramine-marble
  labels:
    marblerun/marbletype: gramine-marble
  annotations:
    sgx.intel.com/quote-provider: aesmd
spec:
  container:
    - name: gramine-marble
      image: localhost/gramine-marble
      resources:
        limits:
          sgx.intel.com/epc: 10Mi
```
