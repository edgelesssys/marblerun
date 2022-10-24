# Command Line Interface (CLI)

We provide a command-line interface (CLI) for MarbleRun.
This CLI allows you to install MarbleRun on your cluster and interacts with the control plane through the Client API for all administrative tasks in the service mesh.

## Installation

To install the MarbleRun CLI on your machine you can use our pre-built binaries.

**For the current user**

```bash
wget -P ~/.local/bin https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
chmod +x ~/.local/bin/marblerun
```

**Global install (requires root)**

```bash
sudo wget -O /usr/local/bin/marblerun https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
sudo chmod +x /usr/local/bin/marblerun
```

To build the MarbleRun CLI, [Edgeless RT](https://github.com/edgelesssys/edgelessrt) needs to be installed on your machine.

```bash
go build -o marblerun github.com/edgelesssys/marblerun/cli
```

To list all available commands, either run `marblerun` with no commands or execute `marblerun help`
The output is the following:

```
Usage:
  marblerun [command]

Available Commands:
  certificate      Retrieves the certificate of the MarbleRun Coordinator
  check            Check the status of MarbleRun's control plane
  completion       Output script for specified shell to enable autocompletion
  gramine-prepare  Modifies a Gramine manifest for use with MarbleRun
  help             Help about any command
  install          Installs marblerun on a kubernetes cluster
  manifest         Manages manifest for the MarbleRun Coordinator
  precheck         Check if your kubernetes cluster supports SGX
  recover          Recovers the MarbleRun Coordinator from a sealed state
  secret           Manages secrets for the MarbleRun Coordinator
  status           Gives information about the status of the marblerun Coordinator
  uninstall        Removes MarbleRun from a kubernetes cluster
  version          Display version of this CLI and (if running) the MarbleRun Coordinator

Flags:
  -h, --help   help for marblerun

Use "marblerun [command] --help" for more information about a command.
```

### Requirements

If the Coordinator is running on an Azure VM, the CLI relies on the [Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client) to verify quotes.
To install the dependency run:
```bash
echo "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" | sudo tee /etc/apt/sources.list.d/msprod.list
wget -qO - https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt update
sudo apt -y install az-dcap-client
```

## Command `certificate`

Get the root and/or intermediate certificates of the MarbleRun Coordinator.

**Flags**
These flags apply to all `certificate` subcommands

| Name, shorthand | Default | Description                                                                                                                      |
| --------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| --era-config    |         | Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github      |
| --help, -h      |         | help for certificate                                                                                                             |
| --insecure, -i  |         | simulation mode                                                                                                                  |
| --output, -o    |         | File to save the certificate to                                                                                                  |

* ### `root`

  Gets the root certificate of the MarbleRun Coordinator.

  **Usage**

  ```bash
  marblerun certificate root <IP:PORT> [flags]
  ```

* ### `intermediate`

  Gets the intermediate certificate of the MarbleRun Coordinator.

  **Usage**

  ```bash
  marblerun certificate intermediate <IP:PORT> [flags]
  ```

* ### `chain`

  Gets the certificate chain of the MarbleRun Coordinator.

  **Usage**

  ```bash
  marblerun certificate chain <IP:PORT> [flags]
  ```

## Command `check`

  Check the status of MarbleRun's control plane.
  This command will check if the MarbleRun Coordinator and/or the MarbleRun webhook are deployed on a Kubernetes cluster and wait until all replicas of the deployment have the `available` status.

  **Usage**

  ```bash
  marblerun check
  ```

  **Flags**

  | Name, shorthand | Default | Description                             |
  | --------------- | ------- | --------------------------------------- |
  | --timeout       | 60      | Time to wait before aborting in seconds |


## Command `completion`
Generate a shell script to enable autocompletion for `marblerun` commands.
Supported shells are:
* `bash`:
  * To enable completion run:
    ```bash
    source <(marblerun completion bash)
    ```

* `zsh`:
  * If completion is not already enabled you need to enable it first:
    ```bash
    echo "autoload -U compinit; compinit" >> ~/.zshrc
    ```
  * Enable completion for `marblerun`:
    ```bash
    marblerun completion zsh > "${fpath[1]}/_marblerun"
    ```


Once enabled, command completion is just one keypress away:\
  `marblerun ma`+<kbd>Tab</kbd> completes to:\
  `marblerun manifest`


## Command `gramine-prepare`
This command helps you if you want to add Gramine-based services to your MarbleRun service mesh.
It prepares your Gramine project to be used as a Marble by replacing the original entrypoint of your application with the bootstrapping Marble premain process which eventually spawns your application.
Given your [Gramine manifest template](https://gramine.readthedocs.io/en/latest/manifest-syntax.html), it will suggest the required adjustments needed and adds our bootstrapping data-plane code to your Gramine image.
See [Building a service: Gramine](building-services/gramine.md) for detailed information on MarbleRun’s Gramine integration and our changes in your Gramine manifest.

Please note that this only works on a best-effort basis and may not instantly work correctly.
While suggestions should be made for every valid TOML Gramine configuration, changes can only be performed for non-hierarchically sorted configurations. as the official Gramine examples.
The unmodified manifest is saved as a backup under the old path with an added ".bak" suffix, allowing you to try out and roll back any changes performed.

Remember, you need to create a [MarbleRun manifest](workflows/define-manifest.md) in addition to the Gramine manifest. Adding Gramine packages to your manifest is straightforward and follows the same principles as any other SGX enclave. If you configured the arguments to your Gramine application through the [Gramine manifest](https://gramine.readthedocs.io/en/latest/manifest-syntax.html#command-line-arguments) before, you need to transfer those to the [MarbleRun manifest](workflows/define-manifest.md#manifestmarbles">}}).

  **Usage**

  ```bash
  marblerun gramine-prepare <path>
  ```

  **Examples**
  ```bash
  marblerun gramine-prepare nginx.manifest.template
  ```

  Output:
  ```bash
  Reading file: nginx.manifest.template

  MarbleRun suggests the following changes to your Gramine manifest:
  libos.entrypoint = "file:premain-libos"
  loader.argv0_override = "$(INSTALL_DIR)/sbin/nginx"
  loader.insecure__use_host_env = 1
  sgx.allowed_files.marblerun_uuid = "file:uuid"
  sgx.enclave_size = "1024M"
  sgx.remote_attestation = 1
  sgx.thread_num = 16
  sgx.trusted_files.marblerun_premain = "file:premain-libos"
  Do you want to automatically apply the suggested changes [y/n]? y
  Applying changes...
  Saving original manifest as nginx.manifest.template.bak...
  Saving changes to nginx.manifest.template...
  Downloading MarbleRun premain from GitHub...
  Successfully downloaded premain-libos.

  Done! You should be good to go for MarbleRun!
  ```

## Command `install`

Install MarbleRun on your Kubernetes cluster.
This command will add MarbleRun to your local helm repository if it is not present yet, optionally you can provide a path to your own helm chart.

**Usage**

```bash
marblerun install [flags]
```

**Flags**

| Name, shorthand          | Default           | Description                                                                                                                                                  |
| :----------------------- | :---------------- | :----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| --client-server-port     | 4433              | Set the client server port. Needs to be configured to the same port as in your client tool stack                                                             |
| --disable-auto-injection |                   | Install MarbleRun without auto-injection webhook                                                                                                             |
| --domain                 | localhost         | Sets the CNAME for the Coordinator certificate                                                                                                               |
| --help, -h               |                   | help for install                                                                                                                                             |
| --marblerun-chart-path   |                   | Path to marblerun helm chart                                                                                                                                 |
| --mesh-sever-port        | 2001              | Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles                                                               |
| --resource-key           | sgx.intel.com/epc | Resource providing SGX, different depending on used device plugin. Use this to set tolerations/resources if your device plugin is not supported by marblerun |
| --simulation             |                   | Set MarbleRun to start in simulation mode, needed when not running on an SGX enabled cluster                                                                 |
| --version                |                   | Version of the Coordinator to install, latest by default                                                                                                     |

**Examples**

* Install MarbleRun on a cluster with SGX Support

    ```bash
    marblerun install --domain=mycluster.uksouth.cloudapp.azure.com
    ```

  The output is similar to the following:

    ```bash
    Did not find marblerun helm repository on system, adding now...
    edgeless has been added to your helm repositories
    Setting up MarbleRun Webhook... Done
    MarbleRun installed successfully
    ```

* Install MarbleRun on a cluster without SGX Support (simulation mode)

    ```bash
    marblerun install --simulation
    ```

  The output is similar to the following:

  ```bash
  Setting up MarbleRun Webhook... Done
  MarbleRun installed successfully
  ```

## Command `manifest`

Set or update a manifest, or retrieve the signature of the manifest in place.

**Flags**
These flags apply to all subcommands of manifest

| Name, shorthand | Default | Description                                                                                                                      |
| --------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| --era-config    |         | Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github      |
| --help, -h      |         | help for manifest                                                                                                                |
| --insecure, -i  |         | simulation mode                                                                                                                  |

* ### `set`

  Uploads a manifest in json or yaml format to the MarbleRun Coordinator.
  If a recovery key was set in the manifest, a recovery secret will be sent back.

  **Usage**

  ```bash
  marblerun manifest set <manifest.json> <IP:PORT> [flags]
  ```

  **Flags**

  | Name, shorthand     | Default | Description                                                |
  | ------------------- | ------- | ---------------------------------------------------------- |
  | --recovery-data, -r |         | File to write recovery data to, print to stdout if not set |

  **Examples**

  ```bash
  marblerun manifest set manifest.json $MARBLERUN --recovery-data=recovery-secret.json --era-config=era.json
  ```

  The output is similar to the following:

  ```bash
  Successfully verified Coordinator, now uploading manifest
  Manifest successfully set, recovery data saved to: recovery-secret.json
  ```

* ### `update`

  Update a manifest by uploading an update manifest to the MarbleRun Coordinator.
  The original manifest has to define one or multiple Users who are allowed to update the manifest.
  For more information see [Update](workflows/update-manifest.md)

  **Usage**

  ```bash
  marblerun manifest update <manifest.json> <IP:PORT> --cert=admin-cert.pem --key=admin-key.pem [flags]
  ```

  **Flags**

  | Name, shorthand | Default | Description                                   |
  | --------------- | ------- | --------------------------------------------- |
  | --cert, -c      |         | PEM encoded admin certificate file (required) |
  | --key, -k       |         | PEM encoded admin key file (required)         |

  **Examples**

  ```bash
  marblerun manifest update update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json
  ```

  The output is the following:

  ```bash
  Successfully verified Coordinator, now uploading manifest
  Manifest successfully updated
  ```

* ### `get`

  Retrieves the manifest and signature from the MarbleRun Coordinator.
  This allows a user to verify what configuration is running on the Coordinator.

  Using the `display-update` flag, users can generate a manifest, including all applied updates up to that point.

  **Usage**

  ```bash
  marblerun manifest get <IP:PORT> [flags]
  ```

  **Flags**

  | Name, shorthand      | Default | Description                                         |
  | -------------------- | --------| --------------------------------------------------- |
  | --display-update, -u |         | Set to merge updates into the displayed manifest    |
  | --output, -o         |         | Save output to file instead of printing to stdout   |
  | --signature, -s      |         | Set to additionally display the manifests signature |

  **Examples**

  ```bash
  marblerun manifest get $MARBLERUN -s --era-config=era.json
  ```

  The output is similar to the following:

  ```bash
  Successfully verified Coordinator, now requesting manifest
  {
  "ManifestSignature": "1ae03179b6e0c4e94546c1a8abff711c8d0975a9ee8ca5445aaa249c22b68724",
  "Manifest": {
      "Packages": {
          "world": {
              "Debug": true
          }
      },
      "Marbles": {
          "hello": {
              "Package": "world",
              "Parameters": {}
          }
      }
  }
  }
  ```

* ### `log`

  Retrieves a structured log of updates to the manifest. This allows users to easily check what the currently supported security versions are and if certain secrets have been set by another user.

  **Usage**

  ```bash
  marblerun manifest log <IP:PORT> [flags]
  ```

  **Flags**

  | Name, shorthand | Default | Description                                    |
  | --------------- | --------| ---------------------------------------------- |
  | --output, -o    |         | Save log to file instead of printing to stdout |

  **Examples**

  ```bash
  marblerun manifest log $MARBLERUN
  ```

  The output is similar to the following:
  ```
  Successfully verified Coordinator, now requesting update log
  Update log:
  {"time":"2021-07-01T09:10:23.128Z","update":"initial manifest set"}
  {"time":"2021-07-01T09:32:54.207Z","update":"secret set","user":"admin","secret":"symmetricKeyUnset","type":"symmetric-key"}
  {"time":"2021-07-01T09:32:54.207Z","update":"secret set","user":"admin","secret":"certUnset","type":"cert-ed25519"}
  {"time":"2021-07-01T10:05:44.791Z","update":"SecurityVersion increased","user":"admin","package":"world","new version":4}
  ```

* ### `signature`

  Print the signature of a MarbleRun manifest.
  The manifest can be in either JSON or YAML format.

  **Usage**

  ```bash
  marblerun manifest signature manifest.json
  ```

  The output is the sha256 hash in base64 encoding of the manifest as it would be interpreted by the MarbleRun Coordinator.
  Note, that Internally, the Coordinator handles the manifest in JSON format. Hence, the signature is always based on the JSON format of your manifest.

* ### `verify`
  Verifies that the signature returned by the Coordinator is equal to a local signature.
  Can be used to quickly verify the integrity of the installed manifest.
  You can provide a signature directly, or a manifest in either JSON or YAML format.

  **Usage**

  ```bash
  marblerun manifest verify <manifest/signature> <IP:PORT> [flags]
  ```

  **Examples**

  ```bash
  marblerun manifest verify manifest.json $MARBLERUN
  ```

  ```bash
  marblerun manifest verify 152493c4a85845480a04b95f79dd447a4573862e0d2c102c71b91b8b3cbcade5 $MARBLERUN
  ```

  If the signatures match, the output is the following:
  ```bash
  OK
  ```

## Command `precheck`

  Check if your Kubernetes cluster supports SGX.
  More precisely the command will check if any nodes in the cluster define SGX resources through the use of [Device Plugins](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/).
  Currently supported are:
  * [Intel SGX Device Plugin](https://intel.github.io/intel-device-plugins-for-kubernetes/cmd/sgx_plugin/README.html), exposing the resources:
    * `sgx.intel.com/enclave`
    * `sgx.intel.com/epc`
    * `sgx.intel.com/provision`


  * [Azure SGX Device Plugin](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-overview#azure-device-plugin-for-intel-sgx-), exposing the resource:
    * `kubernetes.azure.com/sgx_epc_mem_in_MiB`

  **Usage**

  ```bash
  marblerun precheck
  ```

  * If your cluster does not support SGX the output is the following:

  ```bash
  Cluster does not support SGX, you may still run MarbleRun in simulation mode
  To install MarbleRun run [marblerun install --simulation]
  ```

  * If your cluster does support SGX the output is similar to the following

  ```bash
  Cluster supports SGX on 2 nodes
  To install MarbleRun run [marblerun install]
  ```

## Command `recover`

Recover the MarbleRun Coordinator from a sealed state by uploading a recovery key.
For more information about Coordinator recovery see [Recovery](workflows/recover-coordinator.md)

**Usage**

```bash
marblerun recover <recovery_key_decrypted> <IP:PORT> [flags]
```

**Flags**

| Name, shorthand | Default | Description                                                                                                                      |
| --------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| --era-config    |         | Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github      |
| --help, -h      |         | help for recover                                                                                                                 |
| --insecure, -i  |         | Set to skip quote verification, needed when running in simulation mode                                                           |

**Examples**

```bash
marblerun recover recovery_key_decrypted $MARBLERUN --era-config=era.json
```

The output is similar to the following:

```bash
Successfully verified Coordinator, now uploading key
Successfully uploaded recovery key and unsealed the MarbleRun Coordinator
```

## Command `secret`

Manages secrets for the Coordinator

**Flags**
These flags apply to all `secret` subcommands

| Name, shorthand | Default | Description                                                                                                                 |
| --------------- | ------- | --------------------------------------------------------------------------------------------------------------------------- |
| --cert, -c      |         | PEM encoded MarbleRun user certificate file (required)                                                                      |
| --era-config    |         | Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github |
| --insecure, -i  |         | Set to skip quote verification, needed when running in simulation mode                                                      |
| --key, -k       |         | PEM encoded MarbleRun user key file (required)                                                                              |

* ### `get`

  Retrieves one or more secrets from the Coordinator. Requires credentials in the form of a private key and self-signed certificate of the corresponding public key. The corresponding user needs to be permitted to access the requested secrets.
  Secrets are returned in JSON format with key data in base64 encoding.

  **Usage**

  ```bash
  marblerun secret get SECRETNAME ... <IP:PORT> [flags]
  ```

  **Flags**

  | Name, shorthand | Default | Description                |
  | --------------- | ------- | -------------------------- |
  | --output, -o    |         | File to save the secret to |

  **Examples**

  ```bash
  marblerun secret get genericSecret symmetricKeyShared $MARBLERUN -c admin.crt -k admin.key
  ```

  The output is similar to the following:

  ```
  genericSecret:
  	Type:          plain
  	Data:          SGVsbG8gZnJvbSB0aGUgTWFyYmxlcnVuIERvY3MhCg==

  symmetricKeyShared:
  	Type:          symmetric-key
  	UserDefined:   false
  	Size:          128
  	Key:           uVGpoJZTRICLccJiVNt9jA==
  ```

* ### `set`

  Sets one or more secrets for the Coordinator. Requires credentials in the form of a private key and a self-signed certificate of the corresponding public key. The corresponding user needs to be permitted to access the requested secrets.
  Secrets to set are specified in a special secrets file in JSON format, or created by the CLI from a PEM encoded certificate and key.
  For more information see [Managing secrets](workflows/managing-secrets.md).

  **Usage**

  ```bash
  marblerun secret set <secret.json> <IP:PORT> [flags]
  ```

  **Flags**

  | Name, shorthand | Default | Description                                  |
  | --------------- | ------- | -------------------------------------------- |
  | --from-pem      |         | set to load a secret from a PEM encoded file |

  **Examples**

  ```bash
  marblerun secret set secret.json $MARBLERUN -c admin.crt -k admin.key
  ```

  ```bash
  marblerun secret set certificate.pem $MARBLERUN -c admin.crt -k admin.key --from-pem certificateSecret
  ```

  The output is the following:
  ```
  Secret successfully set
  ```

## Command `status`

Checks on the current status of the Coordinator.

**Usage**

```bash
marblerun status <IP:PORT> [flags]
```

**Flags**

| Name, shorthand | Default | Description                                                                                                                      |
| --------------- | ------- | -------------------------------------------------------------------------------------------------------------------------------- |
| --era-config    |         | Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github      |
| --help, -h      |         | help for status                                                                                                                  |
| --insecure, -i  |         | Set to skip quote verification, needed when running in simulation mode                                                           |

**Examples**

```bash
marblerun status $MARBLERUN
```

The output is similar to the following:

```bash
No era config file specified, getting latest config from github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json
Got latest config
2: Coordinator is ready to accept a manifest.
```

## Command `uninstall`

  Remove MarbleRun from your Kubernetes cluster.
  This command will remove all resources added by the installation command.

  **Usage**

  ```bash
  marblerun uninstall
  ```

  The output is the following:
  ```bash
  MarbleRun successfully removed from your cluster
  ```

## Command `version`

  Display version information of CLI, and the MarbleRun Coordinator running on a Kubernetes cluster.

  **Usage**

  ```bash
  marblerun version
  ```

  The output is similar to the following:

  ```
  CLI Version: v0.3.0
  Commit: 689787ea6f3ea3e047a68e2d4deaf095d1d84db9
  Coordinator Version: v0.3.0
  ```
