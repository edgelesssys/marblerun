# Command Line Interface (CLI)

We provide a command-line interface (CLI) for MarbleRun.
This CLI allows you to install MarbleRun on your cluster and interacts with the control plane through the Client API for all administrative tasks in the service mesh.

## Installation

To install the MarbleRun CLI on your machine you can use our pre-built binaries.

<tabs groupId="user">
<tabItem value="current-user" label="For the current user">

```bash
wget -P ~/.local/bin https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
chmod +x ~/.local/bin/marblerun
```

</tabItem>
<tabItem value="global" label="Global install (requires root)">

```bash
sudo wget -O /usr/local/bin/marblerun https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
sudo chmod +x /usr/local/bin/marblerun
```

</tabItem>
<tabItem value="build" label="Build from source">

To build the MarbleRun CLI, [Edgeless RT](https://github.com/edgelesssys/edgelessrt) needs to be installed on your machine.

```bash
git clone https://github.com/edgelesssys/marblerun && cd ./marblerun
go build -buildvcs=false -o marblerun ./cli
```

</tabItem>
</tabs>

### Requirements

The CLI requires SGX quote verification library to verify quotes issued by the Coordinator.
You have different options depending on the environment the Coordinator is deployed to:

<tabs groupId="environement">
<tabItem value="azure" label="Azure CVM">
If the Coordinator is running on an Azure VM, the CLI relies on the [Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client) to verify quotes.
To install the dependency on Ubuntu 20.04 run:

```bash
sudo apt-key adv --fetch-keys https://packages.microsoft.com/keys/microsoft.asc
sudo add-apt-repository 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main'
sudo apt update
sudo apt install -y az-dcap-client
```

</tabItem>
<tabItem value="generic" label="Generic SGX system">

Intel provides the `libsgx-dcap-default-qpl` library to facilitate SGX quote verification.
To install the dependency on Ubuntu 20.04 run:

```bash
sudo apt-key adv --fetch-keys https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
sudo add-apt-repository 'https://download.01.org/intel-sgx/sgx_repo/ubuntu main'
sudo apt update
sudo apt install -y libsgx-dcap-default-qpl
```

Follow the [Intel's documentation](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/qpl/README.md#configuration) to configure access to the PCCS.
</tabItem>
</tabs>

## Reference

Usage:

```terminal
marblerun [command]
```
Commands:

* [certificate](#marblerun-certificate): Retrieves the certificate of the MarbleRun Coordinator
  * [root](#marblerun-certificate-root): Returns the root certificate of the MarbleRun Coordinator
  * [intermediate](#marblerun-certificate-intermediate): Returns the intermediate certificate of the MarbleRun Coordinator
  * [chain](#marblerun-certificate-chain): Returns the certificate chain of the MarbleRun Coordinator
* [check](#marblerun-check): Check the status of MarbleRun's control plane
* [completion](#marblerun-completion): Output script for specified shell to enable autocompletion
* [gramine-prepare](#marblerun-gramine-prepare): Modifies a Gramine manifest for use with MarbleRun
* [install](#marblerun-install): Installs MarbleRun on a kubernetes cluster
* [manifest](#marblerun-manifest): Manages manifest for the MarbleRun Coordinator
  * [get](#marblerun-manifest-get): Get the manifest from the MarbleRun Coordinator
  * [log](#marblerun-manifest-log): Get the update log from the MarbleRun Coordinator
  * [set](#marblerun-manifest-set): Sets the manifest for the MarbleRun Coordinator
  * [signature](#marblerun-manifest-signature): Prints the signature of a MarbleRun manifest
  * [update](#marblerun-manifest-update): Updates the MarbleRun Coordinator with the specified manifest
  * [verify](#marblerun-manifest-verify): Verifies the signature of a MarbleRun manifest
* [precheck](#marblerun-precheck): Check if your kubernetes cluster supports SGX
* [package-info](#marblerun-package-info): Prints the package signature properties of an enclave
* [recover](#marblerun-recover): Recovers the MarbleRun Coordinator from a sealed state
* [secret](#marblerun-secret): Manages secrets for the MarbleRun Coordinator
  * [set](#marblerun-secret-set): Set a secret for the MarbleRun Coordinator
  * [get](#marblerun-secret-get): Retrieve secrets from the MarbleRun Coordinator
* [status](#marblerun-status): Gives information about the status of the MarbleRun Coordinator
* [uninstall](#marblerun-uninstall): Removes MarbleRun from a kubernetes cluster
* [version](#marblerun-version): Display version of this CLI and (if running) the MarbleRun Coordinator

## marblerun certificate

Retrieves the certificate of the MarbleRun Coordinator

### Synopsis

Retrieves the certificate of the MarbleRun Coordinator

### Options

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -h, --help                            help for certificate
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun certificate root

Returns the root certificate of the MarbleRun Coordinator

### Synopsis

Returns the root certificate of the MarbleRun Coordinator

```
marblerun certificate root <IP:PORT> [flags]
```

### Options

```
  -h, --help            help for root
  -o, --output string   File to save the certificate to (default "marblerunRootCA.crt")
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun certificate intermediate

Returns the intermediate certificate of the MarbleRun Coordinator

### Synopsis

Returns the intermediate certificate of the MarbleRun Coordinator

```
marblerun certificate intermediate <IP:PORT> [flags]
```

### Options

```
  -h, --help            help for intermediate
  -o, --output string   File to save the certificate to (default "marblerunIntermediateCA.crt")
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun certificate chain

Returns the certificate chain of the MarbleRun Coordinator

### Synopsis

Returns the certificate chain of the MarbleRun Coordinator

```
marblerun certificate chain <IP:PORT> [flags]
```

### Options

```
  -h, --help            help for chain
  -o, --output string   File to save the certificate to (default "marblerunChainCA.crt")
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun check

Check the status of MarbleRun's control plane

### Synopsis

Check the status of MarbleRun's control plane

```
marblerun check [flags]
```

### Options

```
  -h, --help           help for check
      --timeout uint   Time to wait before aborting in seconds (default 60)
```

## marblerun completion

Output script for specified shell to enable autocompletion

### Synopsis

Output script for specified shell to enable autocompletion

```
marblerun completion
```

### Examples

```

  	For bash:
  	source <(marblerun completion bash)

	For zsh:
	If shell completion is not already enabled in your environment you will need to enable it:
	echo "autoload -U compinit; compinit" >> ~/.zshrc

	To load completions for each session, execute once:
	marblerun completion zsh > "${fpath[1]}/_marblerun"
	
```

### Options

```
  -h, --help   help for completion
```

## marblerun gramine-prepare

Modifies a Gramine manifest for use with MarbleRun

### Synopsis

Modifies a Gramine manifest for use with MarbleRun.

This command tries to automatically adjust the required parameters in an already existing Gramine manifest template, simplifying the migration of your existing Gramine application to MarbleRun.
Please note that you still need to manually create a MarbleRun manifest.

For more information about the requirements and  changes performed, consult the documentation: https://edglss.cc/doc-mr-gramine

The parameter of this command is the path of the Gramine manifest template you want to modify.


```
marblerun gramine-prepare [flags]
```

### Options

```
  -h, --help   help for gramine-prepare
```

## marblerun install

Installs MarbleRun on a kubernetes cluster

### Synopsis

Installs MarbleRun on a Kubernetes cluster

```
marblerun install [flags]
```

### Examples

```
# Install MarbleRun in simulation mode
marblerun install --simulation

# Install MarbleRun using the Intel QPL and custom PCCS
marblerun install --dcap-qpl intel --dcap-pccs-url https://pccs.example.com/sgx/certification/v3/ --dcap-secure-cert FALSE
```

### Options

```
      --client-server-port int        Set the client server port. Needs to be configured to the same port as in your client tool stack (default 4433)
      --dcap-pccs-url string          Provisioning Certificate Caching Service (PCCS) server address (default "https://localhost:8081/sgx/certification/v3/")
      --dcap-qpl string               Quote provider library to use by the Coordinator. One of {"azure", "intel"} (default "azure")
      --dcap-secure-cert string       To accept insecure HTTPS certificate from the PCCS, set this option to FALSE (default "TRUE")
      --disable-auto-injection        Install MarbleRun without auto-injection webhook
      --domain string                 Sets the CNAME for the Coordinator certificate (default "localhost")
  -h, --help                          help for install
      --marblerun-chart-path string   Path to MarbleRun helm chart
      --mesh-server-port int          Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles (default 2001)
      --resource-key string           Resource providing SGX, different depending on used device plugin. Use this to set tolerations/resources if your device plugin is not supported by MarbleRun
      --simulation                    Set MarbleRun to start in simulation mode
      --version string                Version of the Coordinator to install, latest by default
```

## marblerun manifest

Manages manifest for the MarbleRun Coordinator

### Synopsis


Manages manifests for the MarbleRun Coordinator.
Used to either set the manifest, update an already set manifest,
or return a signature of the currently set manifest to the user

### Examples

```
manifest set manifest.json example.com:4433 [--era-config=config.json] [--insecure]
```

### Options

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -h, --help                            help for manifest
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun manifest get

Get the manifest from the MarbleRun Coordinator

### Synopsis

Get the manifest from the MarbleRun Coordinator.
Optionally get the manifests signature or merge updates into the displayed manifest.

```
marblerun manifest get <IP:PORT> [flags]
```

### Examples

```
marblerun manifest get $MARBLERUN -s --era-config=era.json
```

### Options

```
  -u, --display-update   Set to merge updates into the displayed manifest
  -h, --help             help for get
  -o, --output string    Save output to file instead of printing to stdout
  -s, --signature        Set to additionally display the manifests signature
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun manifest log

Get the update log from the MarbleRun Coordinator

### Synopsis

Get the update log from the MarbleRun Coordinator.
		The log is list of all successful changes to the Coordinator,
		including a timestamp and user performing the operation.

```
marblerun manifest log <IP:PORT> [flags]
```

### Examples

```
marblerun manifest log $MARBLERUN
```

### Options

```
  -h, --help            help for log
  -o, --output string   Save log to file instead of printing to stdout
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun manifest set

Sets the manifest for the MarbleRun Coordinator

### Synopsis

Sets the manifest for the MarbleRun Coordinator

```
marblerun manifest set <manifest.json> <IP:PORT> [flags]
```

### Examples

```
marblerun manifest set manifest.json $MARBLERUN --recovery-data=recovery-secret.json --era-config=era.json
```

### Options

```
  -h, --help                  help for set
  -r, --recoverydata string   File to write recovery data to, print to stdout if non specified
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun manifest signature

Prints the signature of a MarbleRun manifest

### Synopsis

Prints the signature of a MarbleRun manifest

```
marblerun manifest signature <manifest.json> [flags]
```

### Options

```
  -h, --help   help for signature
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun manifest update

Updates the MarbleRun Coordinator with the specified manifest

### Synopsis


Updates the MarbleRun Coordinator with the specified manifest.
An admin certificate specified in the original manifest is needed to verify the authenticity of the update manifest.


```
marblerun manifest update <manifest.json> <IP:PORT> [flags]
```

### Examples

```
marblerun manifest update update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json
```

### Options

```
  -c, --cert string   PEM encoded admin certificate file (required)
  -h, --help          help for update
  -k, --key string    PEM encoded admin key file (required)
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun manifest verify

Verifies the signature of a MarbleRun manifest

### Synopsis

Verifies that the signature returned by the Coordinator is equal to a local signature

```
marblerun manifest verify <manifest/signature> <IP:PORT> [flags]
```

### Examples

```
marblerun manifest verify manifest.json $MARBLERUN
```

### Options

```
  -h, --help   help for verify
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun precheck

Check if your kubernetes cluster supports SGX

### Synopsis

Check if your kubernetes cluster supports SGX

```
marblerun precheck [flags]
```

### Options

```
  -h, --help   help for precheck
```

## marblerun package-info

Prints the package signature properties of an enclave

### Synopsis

Prints the package signature properties of an enclave

```
marblerun package-info [flags]
```

### Options

```
  -h, --help   help for package-info
```

## marblerun recover

Recovers the MarbleRun Coordinator from a sealed state

### Synopsis

Recovers the MarbleRun Coordinator from a sealed state

```
marblerun recover <recovery_key_decrypted> <IP:PORT> [flags]
```

### Examples

```
marblerun recover recovery_key_decrypted $MARBLERUN
```

### Options

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -h, --help                            help for recover
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun secret

Manages secrets for the MarbleRun Coordinator

### Synopsis


Manages secrets for the MarbleRun Coordinator.
Set or retrieve a secret defined in the manifest.

### Options

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
  -c, --cert string                     PEM encoded MarbleRun user certificate file (required)
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -h, --help                            help for secret
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -k, --key string                      PEM encoded MarbleRun user key file (required)
```

## marblerun secret set

Set a secret for the MarbleRun Coordinator

### Synopsis


Set a secret for the MarbleRun Coordinator.
Secrets are loaded from a file in JSON format or directly from a PEM
encoded certificate and/or key. In the later case, the name of the secret
has to be set with the flag [--from-pem].
Users have to authenticate themselves using a certificate and private key
and need permissions in the manifest to write the requested secrets.


```
marblerun secret set <secret_file> <IP:PORT> [flags]
```

### Examples

```
# Set a secret from a JSON file
marblerun secret set secret.json $MARBLERUN -c admin.crt -k admin.key

# Set a secret from a PEM encoded file
marblerun secret set certificate.pem $MARBLERUN -c admin.crt -k admin.key --from-pem certificateSecret
```

### Options

```
      --from-pem string   name of the secret from a PEM encoded file
  -h, --help              help for set
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
  -c, --cert string                     PEM encoded MarbleRun user certificate file (required)
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -k, --key string                      PEM encoded MarbleRun user key file (required)
```

## marblerun secret get

Retrieve secrets from the MarbleRun Coordinator

### Synopsis


Retrieve one or more secrets from the MarbleRun Coordinator.
Users have to authenticate themselves using a certificate and private key,
and need permissions in the manifest to read the requested secrets.


```
marblerun secret get SECRETNAME ... <IP:PORT> [flags]
```

### Examples

```
marblerun secret get genericSecret symmetricKeyShared $MARBLERUN -c admin.crt -k admin.key
```

### Options

```
  -h, --help            help for get
  -o, --output string   File to save the secret to
```

### Options inherited from parent commands

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
  -c, --cert string                     PEM encoded MarbleRun user certificate file (required)
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -k, --key string                      PEM encoded MarbleRun user key file (required)
```

## marblerun status

Gives information about the status of the MarbleRun Coordinator

### Synopsis


This command provides information about the currently running MarbleRun Coordinator.
Information is obtained from the /status endpoint of the Coordinators REST API.

The Coordinator will be in one of these 4 states:
  0 recovery mode: Found a sealed state of an old seal key. Waiting for user input on /recovery.
	The Coordinator is currently sealed, it can be recovered using the [marblerun recover] command.

  1 uninitialized: Fresh start, initializing the Coordinator.
	The Coordinator is in its starting phase.

  2 waiting for manifest: Waiting for user input on /manifest.
	Send a manifest to the Coordinator using [marblerun manifest set] to start.

  3 accepting marble: The Coordinator is running, you can add marbles to the mesh or update the
    manifest using [marblerun manifest update].


```
marblerun status <IP:PORT> [flags]
```

### Options

```
      --accepted-tcb-statuses strings   Comma separated list of user accepted TCB statuses (e.g. ConfigurationNeeded,ConfigurationAndSWHardeningNeeded) (default [UpToDate])
      --era-config string               Path to remote attestation config file in json format, if none provided the newest configuration will be loaded from github
  -h, --help                            help for status
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
```

## marblerun uninstall

Removes MarbleRun from a kubernetes cluster

### Synopsis

Removes MarbleRun from a kubernetes cluster

```
marblerun uninstall [flags]
```

### Options

```
  -h, --help   help for uninstall
```

## marblerun version

Display version of this CLI and (if running) the MarbleRun Coordinator

### Synopsis

Display version of this CLI and (if running) the MarbleRun Coordinator

```
marblerun version [flags]
```

### Options

```
  -h, --help   help for version
```

