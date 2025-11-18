# Command Line Interface (CLI)

The MarbleRun CLI allows you to install MarbleRun on your cluster and interacts with the control plane through the Client API for all administrative tasks in the service mesh.

## Reference

Usage:

```terminal
marblerun [command]
```
Commands:

* [install](#marblerun-install): Installs MarbleRun on a Kubernetes cluster
* [uninstall](#marblerun-uninstall): Remove MarbleRun from a Kubernetes cluster
* [precheck](#marblerun-precheck): Check if your Kubernetes cluster supports SGX
* [check](#marblerun-check): Check the status of MarbleRun's control plane
* [manifest](#marblerun-manifest): Manages manifest for the MarbleRun Coordinator
  * [get](#marblerun-manifest-get): Get the manifest from the MarbleRun Coordinator
  * [log](#marblerun-manifest-log): Get the update log from the MarbleRun Coordinator
  * [set](#marblerun-manifest-set): Sets the manifest for the MarbleRun Coordinator
  * [signature](#marblerun-manifest-signature): Prints the signature of a MarbleRun manifest
  * [update](#marblerun-manifest-update): Manage manifest updates for the MarbleRun Coordinator
    * [apply](#marblerun-manifest-update-apply): Update the MarbleRun Coordinator with the specified manifest
    * [acknowledge](#marblerun-manifest-update-acknowledge): Acknowledge a pending update for the MarbleRun Coordinator
    * [cancel](#marblerun-manifest-update-cancel): Cancel a pending manifest update for the MarbleRun Coordinator
    * [get](#marblerun-manifest-update-get): View a pending manifest update
  * [verify](#marblerun-manifest-verify): Verify the signature of a MarbleRun manifest
* [certificate](#marblerun-certificate): Retrieves the certificate of the MarbleRun Coordinator
  * [root](#marblerun-certificate-root): Returns the root certificate of the MarbleRun Coordinator
  * [intermediate](#marblerun-certificate-intermediate): Returns the intermediate certificate of the MarbleRun Coordinator
  * [chain](#marblerun-certificate-chain): Returns the certificate chain of the MarbleRun Coordinator
* [secret](#marblerun-secret): Manage secrets for the MarbleRun Coordinator
  * [set](#marblerun-secret-set): Set a secret for the MarbleRun Coordinator
  * [get](#marblerun-secret-get): Retrieve secrets from the MarbleRun Coordinator
* [status](#marblerun-status): Retrieve information about the status of the MarbleRun Coordinator
* [recover](#marblerun-recover): Recover the MarbleRun Coordinator from a sealed state
* [package-info](#marblerun-package-info): Print the package signature properties of an enclave
* [version](#marblerun-version): Display version of this CLI and (if running) the MarbleRun Coordinator

## marblerun install

Installs MarbleRun on a Kubernetes cluster

### Synopsis

Installs MarbleRun on a Kubernetes cluster

```
marblerun install [flags]
```

### Examples

```
# Install MarbleRun in simulation mode
marblerun install --simulation

# Install MarbleRun using a custom PCCS
marblerun install --dcap-pccs-url https://pccs.example.com/sgx/certification/v4/ --dcap-secure-cert FALSE
```

### Options

```
      --client-server-port int         Set the client server port. Needs to be configured to the same port as in your client tool stack (default 4433)
      --dcap-pccs-url string           Provisioning Certificate Caching Service (PCCS) server address. Defaults to Azure PCCS. Mutually exclusive with "--dcap-qcnl-config-file" (default "https://global.acccache.azure.net/sgx/certification/v4/")
      --dcap-qcnl-config-file string   Path to a custom QCNL configuration file. Mutually exclusive with "--dcap-pccs-url" and "--dcap-secure-cert".
      --dcap-secure-cert string        To accept insecure HTTPS certificate from the PCCS, set this option to FALSE. Mutually exclusive with "--dcap-qcnl-config-file" (default "TRUE")
      --disable-auto-injection         Install MarbleRun without auto-injection webhook
      --distributed-deployment         Install MarbleRun in distributed deployment mode.
      --domain strings                 Sets additional DNS names and IPs for the Coordinator TLS certificate
  -h, --help                           help for install
      --marblerun-chart-path string    Path to MarbleRun helm chart
      --mesh-server-port int           Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles (default 2001)
      --resource-key string            Resource providing SGX, different depending on used device plugin. Use this to set tolerations/resources if your device plugin is not supported by MarbleRun
      --simulation                     Set MarbleRun to start in simulation mode
      --version string                 Version of the Coordinator to install, latest by default
      --wait                           Wait for MarbleRun installation to complete before returning
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun uninstall

Remove MarbleRun from a Kubernetes cluster

### Synopsis

Remove MarbleRun from a Kubernetes cluster

```
marblerun uninstall [flags]
```

### Options

```
  -h, --help   help for uninstall
      --wait   Wait for the uninstallation to complete before returning
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun precheck

Check if your Kubernetes cluster supports SGX

### Synopsis

Check if your Kubernetes cluster supports SGX

```
marblerun precheck [flags]
```

### Options

```
  -h, --help   help for precheck
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
  -h, --help   help for manifest
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --keep-cert        Set to keep the certificate of the Coordinator and save it to the location specified by --coordinator-cert
  -o, --output string    Save output to file instead of printing to stdout
  -s, --signature        Set to additionally display the manifests signature
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun manifest update

Manage manifest updates for the MarbleRun Coordinator

### Synopsis

Manage manifest updates for the MarbleRun Coordinator.

### Options

```
  -h, --help   help for update
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun manifest update apply

Update the MarbleRun Coordinator with the specified manifest

### Synopsis


Update the MarbleRun Coordinator with the specified manifest.
An admin certificate specified in the original manifest is needed to verify the authenticity of the update manifest.


```
marblerun manifest update apply <manifest.json> <IP:PORT> [flags]
```

### Examples

```
marblerun manifest update apply update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json
```

### Options

```
  -c, --cert string                PEM encoded MarbleRun user certificate file
  -h, --help                       help for apply
  -k, --key string                 PEM encoded MarbleRun user key file
      --pkcs11-cert-id string      ID of the certificate in the PKCS#11 token
      --pkcs11-cert-label string   Label of the certificate in the PKCS#11 token
      --pkcs11-config string       Path to a PKCS#11 configuration file to load the client certificate with
      --pkcs11-key-id string       ID of the private key in the PKCS#11 token
      --pkcs11-key-label string    Label of the private key in the PKCS#11 token
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun manifest update acknowledge

Acknowledge a pending update for the MarbleRun Coordinator

### Synopsis

Acknowledge a pending update for the MarbleRun Coordinator.

In case of multi-party updates, the Coordinator will wait for all participants to acknowledge the update before applying it.
All participants must use the same manifest to acknowledge the pending update.


```
marblerun manifest update acknowledge <manifest.json> <IP:PORT> [flags]
```

### Examples

```
marblerun manifest update acknowledge update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json
```

### Options

```
  -c, --cert string                PEM encoded MarbleRun user certificate file
  -h, --help                       help for acknowledge
  -k, --key string                 PEM encoded MarbleRun user key file
      --pkcs11-cert-id string      ID of the certificate in the PKCS#11 token
      --pkcs11-cert-label string   Label of the certificate in the PKCS#11 token
      --pkcs11-config string       Path to a PKCS#11 configuration file to load the client certificate with
      --pkcs11-key-id string       ID of the private key in the PKCS#11 token
      --pkcs11-key-label string    Label of the private key in the PKCS#11 token
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun manifest update cancel

Cancel a pending manifest update for the MarbleRun Coordinator

### Synopsis

Cancel a pending manifest update for the MarbleRun Coordinator.

```
marblerun manifest update cancel <IP:PORT> [flags]
```

### Examples

```
marblerun manifest update cancel $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json
```

### Options

```
  -c, --cert string                PEM encoded MarbleRun user certificate file
  -h, --help                       help for cancel
  -k, --key string                 PEM encoded MarbleRun user key file
      --pkcs11-cert-id string      ID of the certificate in the PKCS#11 token
      --pkcs11-cert-label string   Label of the certificate in the PKCS#11 token
      --pkcs11-config string       Path to a PKCS#11 configuration file to load the client certificate with
      --pkcs11-key-id string       ID of the private key in the PKCS#11 token
      --pkcs11-key-label string    Label of the private key in the PKCS#11 token
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun manifest update get

View a pending manifest update

### Synopsis

View a pending manifest update.

```
marblerun manifest update get <IP:PORT> [flags]
```

### Examples

```
marblerun manifest update get $MARBLERUN --era-config=era.json
```

### Options

```
  -h, --help            help for get
      --missing         Display number of missing acknowledgements instead of the manifest
  -o, --output string   Save output to file instead of printing to stdout
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun manifest verify

Verify the signature of a MarbleRun manifest

### Synopsis

Verify that the signature returned by the Coordinator is equal to a local signature

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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun certificate

Retrieves the certificate of the MarbleRun Coordinator

### Synopsis

Retrieves the certificate of the MarbleRun Coordinator

### Options

```
  -h, --help   help for certificate
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun secret

Manage secrets for the MarbleRun Coordinator

### Synopsis


Manage secrets for the MarbleRun Coordinator.
Set or retrieve a secret defined in the manifest.

### Options

```
  -c, --cert string                PEM encoded MarbleRun user certificate file
  -h, --help                       help for secret
  -k, --key string                 PEM encoded MarbleRun user key file
      --pkcs11-cert-id string      ID of the certificate in the PKCS#11 token
      --pkcs11-cert-label string   Label of the certificate in the PKCS#11 token
      --pkcs11-config string       Path to a PKCS#11 configuration file to load the client certificate with
      --pkcs11-key-id string       ID of the private key in the PKCS#11 token
      --pkcs11-key-label string    Label of the private key in the PKCS#11 token
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
  -c, --cert string                     PEM encoded MarbleRun user certificate file
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -k, --key string                      PEM encoded MarbleRun user key file
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --pkcs11-cert-id string           ID of the certificate in the PKCS#11 token
      --pkcs11-cert-label string        Label of the certificate in the PKCS#11 token
      --pkcs11-config string            Path to a PKCS#11 configuration file to load the client certificate with
      --pkcs11-key-id string            ID of the private key in the PKCS#11 token
      --pkcs11-key-label string         Label of the private key in the PKCS#11 token
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
  -c, --cert string                     PEM encoded MarbleRun user certificate file
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -k, --key string                      PEM encoded MarbleRun user key file
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --pkcs11-cert-id string           ID of the certificate in the PKCS#11 token
      --pkcs11-cert-label string        Label of the certificate in the PKCS#11 token
      --pkcs11-config string            Path to a PKCS#11 configuration file to load the client certificate with
      --pkcs11-key-id string            ID of the private key in the PKCS#11 token
      --pkcs11-key-label string         Label of the private key in the PKCS#11 token
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun status

Retrieve information about the status of the MarbleRun Coordinator

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
  -h, --help   help for status
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun recover

Recover the MarbleRun Coordinator from a sealed state

### Synopsis

Recover the MarbleRun Coordinator from a sealed state.
`recovery_key_file` may be either a decrypted recovery secret, or an encrypted recovery secret,
in which case the private key is used to decrypt the secret.

```
marblerun recover <recovery_key_file> <IP:PORT> [flags]
```

### Examples

```
marblerun recover recovery_key_file $MARBLERUN
```

### Options

```
  -h, --help                      help for recover
  -k, --key string                Path to a the recovery private key to decrypt and/or sign the recovery key
      --pkcs11-config string      Path to a PKCS#11 configuration file to load the recovery private key with
      --pkcs11-key-id string      ID of the private key in the PKCS#11 token
      --pkcs11-key-label string   Label of the private key in the PKCS#11 token
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

## marblerun package-info

Print the package signature properties of an enclave

### Synopsis

Print the package signature properties of an enclave

```
marblerun package-info [flags]
```

### Options

```
  -h, --help   help for package-info
```

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
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

### Options inherited from parent commands

```
      --accepted-advisories strings     Comma-separated list of user accepted Intel Security Advisories for SWHardeningNeeded TCB status. If empty, all advisories are accepted
      --accepted-tcb-statuses strings   Comma-separated list of user accepted TCB statuses (default [UpToDate,SWHardeningNeeded])
      --coordinator-cert string         Path to MarbleRun Coordinator's root certificate to use for TLS connections (default "$HOME/.config/marblerun/coordinator-cert.pem")
      --era-config string               Path to a remote-attestation config file in JSON format. If none is provided, the command attempts to use './coordinator-era.json'. If that does not exist, the command will attempt to load a matching config file from the MarbleRun GitHub repository
  -i, --insecure                        Set to skip quote verification, needed when running in simulation mode
  -n, --namespace string                Kubernetes namespace of the MarbleRun installation (default "marblerun")
      --nonce string                    (Optional) nonce to use for quote verification. If set, the Coordinator will generate a quote over sha256(CoordinatorCert + nonce)
      --save-sgx-quote string           If set, save the Coordinator's SGX quote to the specified file
```

