# Building a service: Gramine
Running a Gramine app with MarbleRun requires some changes to its manifest. These are explained in the following. See also the [hello world example](https://github.com/edgelesssys/marblerun/tree/master/samples/gramine-hello).

## Requirements
First, get Gramine up and running. Gramine is available [as a Debian package](https://github.com/gramineproject/gramine/releases). Alternatively you can follow either the [Building](https://gramine.readthedocs.io/en/latest/devel/building.html) or [Cloud Deployment](https://gramine.readthedocs.io/en/latest/cloud-deployment.html) guide to build and install Gramine from source.

Before running your application, make sure you got the prerequisites for ECDSA remote attestation installed on your system. You can collectively install them with the following command:
```sh
sudo apt install libsgx-quote-ex-dev
```
## Configuration
### Entrypoint and argv
We provide the `premain-libos` executable with the [MarbleRun Releases](https://github.com/edgelesssys/marblerun/releases). It will contact the Coordinator, set up the environment, and run the actual application.

Set the premain executable as the entry point of the Gramine project and place the actual entry point in argv0:
```toml
libos.entrypoint = "file:premain-libos"

# argv0 needs to contain the name of your executable
loader.argv0_override = "hello"

# add the premain to the list of trusted files
sgx.trusted_files = [
    # ...
    "file:premain-libos"
]
```
After the premain is done running, it will automatically spawn your application.

### Host environment variables
The premain needs access to some host [environment variables for configuration](workflows/add-service.md#step-3-start-your-service):
```toml
loader.env.EDG_MARBLE_TYPE = { passthrough = true }
loader.env.EDG_MARBLE_COORDINATOR_ADDR = { passthrough = true }
loader.env.EDG_MARBLE_UUID_FILE = { passthrough = true }
loader.env.EDG_MARBLE_DNS_NAMES = { passthrough = true }
```

### UUID file
The Marble must be able to store its UUID:
```toml
sgx.allowed_files.uuid = "file:uuid"
```

### Remote attestation
The Marble will send an SGX quote to the Coordinator for remote attestation:
```toml
sgx.remote_attestation = true
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
fs.mount.secrets.type = "tmpfs"
fs.mount.secrets.path = "/secrets"
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

Note that Gramine also allows to store files encrypted on the host's file system. The so called `protected files` require to initialize the protected files key by writing it hex-encoded to the virtual `protected_files_key` device:

```
sgx.protected_files_key = "[16-byte hex value]"
sgx.protected_files.[identifier] = "[URI]"
```
You can see how this key can be initialized with MarbleRun in the [nginx example](https://github.com/edgelesssys/marblerun/tree/master/samples/gramine-nginx).

## Troubleshooting
### aesm_service returned error: 30
If you receive the following error message on launch:

```
aesm_service returned error: 30
load_enclave() failed with error -1
```

Make sure you installed the Intel AESM ECDSA plugins on your machine. You can do this by installing the `libsgx-quote-dev` package mentioned in the requirements above.
