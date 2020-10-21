# Overview

Edgeless Mesh consists of two logic parts, the control plane called *Coordinator* and the data plane called *Marbles*.
The *Coordinator* needs to be deployed once in your cluster and the *Marble* layer needs to be integrated with each service.
Edgeless Mesh is configured with a simple JSON document called the *Manifest*.
It specifies the topology of the distributed app, the infrastructure properties, and provides configuration parameters for each service.

![overview](assets/mesh_overview.svg)

## Manifest

The manifest is a simple JSON file specifying three asset groups: *Packages*, *Infrastructures*, and *Marbles*:

### Manifest:Packages

A package defines a specific container image in your application.
It contains the secure enclave's measurements and associated properties:

* **UniqueID**: The enclave's unique identifying measurement, called MRENCLAVE on SGX
* **SignerID**: The signer's unique identifier, called MRSIGNER on SGX
* **ProductID**: The unique identifier of your product associated with the enclave
* **SecurityVersion**: The version number of your product associated with the enclave
* **Debug**: A flag indicating whether your enclave should be run in debug mode

You can use any combination of these values depending on how you want to identify the image.
For each confidential container you want to run in your cluster, you need to add an entry in the *Packages* section of the manifest.

```json
    "Packages": {
        "backend": {
            "UniqueID": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "SignerID": "c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee",
            "ProductID": [1337],
            "SecurityVersion": 1,
            "Debug": false
        },
        "frontend": {
            "UniqueID": "1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100",
            "ProductID": [42],
            "SecurityVersion": 3,
            "Debug": true
        }
    }
```

### Manifest:Infrastructures

*Infrastructures* defines several VM types you want to whitelist for your application to run on.
This way you can make sure that when you deploy your application to a cluster with VM of type A, nobody can substitute one of the nodes with a VM of type B.
Each entry contains certain values that uniquely identify the hardware:

* **QESVN**: The Quoting Enclaves version number
* **PCESVN**: The Provisioning Certificate Enclave version number
* **CPUSVN**: The CPU version number
* **RootCA**: The Root Certificate of the remote attestation chain

```json
    "Infrastructures": {
        "Azure": {
            "QESVN": 2,
            "PCESVN": 3,
            "CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
            "RootCA": [3,3,3]
        },
        "Alibaba": {
            "QESVN": 2,
            "PCESVN": 4,
            "CPUSVN": [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
            "RootCA": [4,4,4]
        }
    }
```

### Manifest:Marbles

Marbles represent the actual service in your mesh.
Each service type corresponds to a *Package* and needs an entry in the *Marbles* section.
An entry contains several optional *Parameters* passed to the secure enclave:

* Files: Files and their contents
* Env: Environment variables
* Argv: Command line arguments

Those *Parameters* can contain placeholder variables that are supported by Edgeless Mesh and result from the authentication process with the *Coordinator*:

* `$$root_ca`: The Root Certificate of the entire Mesh issued by the *Coordinator*. It can be used to verify the service-specific *Marble* certificates
* `$$marble_cert`: The Marble's specific certificate. It can be used by the Marble for server- and client-authentication
* `$$marble_key`: The corresponding private key for the `$$marble_cert`
* `$$seal_key`: A symmetric key that can be used for sealing data to the disc in a hardware-independent way. If the Marble is scheduled or restarted on another node this virtual sealing key will allow unsealing the data from the disk even though the hardware's sealing key might have changed.

```json
    "Marbles": {
        "backend_first": {
            "Package": "backend",
            "MaxActivations": 1,
            "Parameters": {
                "Files": {
                    "/tmp/defg.txt": "foo",
                    "/tmp/jkl.mno": "bar"
                },
                "Env": {
                    "IS_FIRST": "true",
                    "ROOT_CA": "$$root_ca",
                    "SEAL_KEY": "$$seal_key",
                    "MARBLE_CERT": "$$marble_cert",
                    "MARBLE_KEY": "$$marble_key"
                },
                "Argv": [
                    "--first",
                    "serve"
                ]
            }
        },
        "frontend": {
            "Package": "frontend",
            "Parameters": {
                "Env": {
                    "ROOT_CA": "$$root_ca",
                    "SEAL_KEY": "$$seal_key",
                    "MARBLE_CERT": "$$marble_cert",
                    "MARBLE_KEY": "$$marble_key"
                }
            }
        }
    }
```

## Coordinator

The Coordinator represents the control plane in Edgeless Mesh.
It communnicates with the data plane through gRPC and provides an HTTP-REST interface on the client-side.
The Coordinator can be configured with several environment variables:

* `EDG_MESH_SERVER_ADDR`: The listener address for the gRPC server
* `EDG_CLIENT_SERVER_ADDR`: The listener address for the HTTP server
* `EDG_COORDINATOR_DNS_NAMES`: The DNS names in the Mesh's Root Certificate
* `EDG_COORDINATOR_SEAL_DIR`: The file path for storing sealed data

### Client API

The Client API is designed as an HTTP-REST interface.
The API currently contains two endpoints:

* `/manifest`: For deploying and verifying the Manifest
    * Example for setting the manifest:

        ```bash
        curl --silent --cacert mesh.crt -X POST -H  "Content-Type: application/json" --data-binary @manifest.json "https://$EDG_COORDINATOR_ADDR/manifest"
        ```

    * Example for verifying the deployed Manifest

        ```bash
        curl --silent --cacert mesh.crt "https://$EDG_COORDINATOR_ADDR/manifest" | jq '.ManifestSignature' --raw-output
        ```

* `/quote`: For retrieving a remote attestation quote over the whole service mesh and the Root Certificate
    * Example for retrieving a quote

        ```bash
        curl --silent -k "https://$EDG_COORDINATOR_ADDR/quote"
        ```

    * We provide a tool to automatically verify the quote and output the trusted certificate:

        ```bash
        go install github.com/edgelesssys/era/cmd/era
        era -c mesh.config -h $EDG_COORDINATOR_ADDR -o mesh.crt
        ```

        * Note that `mesh.config` contains the *Packages* information for the Coordinator. For our testing image this can be pulled from our GitHub releases:

        ```bash
        curl -s https://api.github.com/repos/edgelesssys/coordinator/releases/latest \
        | grep "mesh.config" \
        | cut -d '"' -f 4 \
        | wget -qi -
        ```

## Marbles

The Marbles represent the data plane in Edgeless Mesh.
They communicate with the Coordinator through gRPC.
For making a confidential service an Edgeless Mesh *Marble* the Marble code needs to be injected into the service's secure enclave.

See [Add a Service](add-service.md) for more information on how to build a Marble.

A Marble can be configured with several environment variables:

* `EDG_COORDINATOR_ADDR`: The Coordinator's address
* `EDG_MARBLE_TYPE`: The Marble's Package
* `EDG_MARBLE_DNS_NAMES`: The DNS names in the Marble's Certificate
* `EDG_MARBLE_UUID_FILE`: The file path for storing the Marble's UUID, needed for restart persistence.
