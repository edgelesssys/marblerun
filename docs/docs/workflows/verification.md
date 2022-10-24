# Verifying a deployment

MarbleRun provides a simple HTTP REST API for clients to verify the confidentiality and integrity of the Coordinator and the deployed Marbles.

## Requirements

Verifying remote attestation quotes does not require an SGX capable machine, however, quote provider libraries are still necessary to perform remote attestation.

### Azure QPL

If the quote was generated on Azure infrastructure, all you need is the [Azure-DCAP-Client](https://github.com/microsoft/Azure-DCAP-Client), which is already configured to connect to the correct Azure-provided [Provisioning Certificate Caching Service (PCCS)](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/DCAP_ECDSA_Orientation.pdf) endpoints.

You can install it via Microsoft's Ubuntu package repository:

```bash
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add
sudo add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/ubuntu/`lsb_release -rs`/prod `lsb_release -cs` main"
sudo apt install az-dcap-client
```

### Intel QPL

Otherwise, you can use the [Intel DCAP Quote Provider Library](https://github.com/intel/SGXDataCenterAttestationPrimitives/tree/master/QuoteGeneration/qpl).
You can install the library via Intel's Ubuntu package repository:
```bash
# Add the repository and key
wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
# Install the qpl
sudo apt install libsgx-dcap-default-qpl
```

Our tools build on [OpenEnclave](https://github.com/openenclave/openenclave) for quote verification, which expects the QPL as `libdcap_quoteprov.so`.
We need to create a link to Intel's library:
```bash
cd /usr/lib/x86_64-linux-gnu/
sudo ln -s libdcap_quoteprov.so.1 libdcap_quoteprov.so
```

To make sure the QPL connects to the correct PCCS we need to edit the [configuration](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/qpl/README.md#configuration) in `/etc/sgx_default_qcnl.conf`.
```
# PCCS server address
PCCS_URL=<YOUR_PCCS_URL>
# To accept insecure HTTPS cert, set this option to FALSE
USE_SECURE_CERT=<TRUE/FALSE>
```



## Establishing trust in the Coordinator

MarbleRun exposes the `/quote` endpoint that returns a quote and a certificate chain consisting of a root and intermediate CA. The root CA is fixed for the lifetime of your deployment, while the intermediate CA changes in case you [update](workflows/update-manifest.md) the packages specified in your manifest.

The simplest way to verify the quote is via the Edgeless Remote Attestation ([era](https://github.com/edgelesssys/era)) tool.

To verify the coordinator, `era` requires the Coordinator's UniqueID (or MRENCLAVE in SGX terms) or the tuple ProductID, SecurityVersion, SignerID (MRSIGNER) to verify the quote. `era` contacts the Coordinator, and receives an SGX quote from it which contains the actual UniqueID or ProductID/SecurityVersion/SignerID tuple of the running instance. The tool verifies it against the values the expected values defined in `coordinator-era.json` and can therefore determine if an authentic copy of the Coordinator is running, or if an unknown version is contacted. 

In production, the expected values in `coordinator-era.json` would be generated when building the Coordinator and distributed to your clients. When you build MarbleRun from source, you can find the file in your build directory.
For testing with a pre-built release, we have published a Coordinator image at `ghcr.io/edgelesssys/coordinator`.
You can pull the corresponding `coordinator-era.json` file from our release page:

```bash
wget https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json
```

After installing `era`, you can verify the quote with the following command:

```bash
era -c coordinator-era.json -h $MARBLERUN -output-chain marblerun-chain.pem -output-root marblerun-root.pem -output-intermediate marblerun-intermedite.pem
```

After successful verification, you'll have `marblerun-chain.pem`, `marblerun-root.pem`, and `marblerun-intermediate.pem` in your directory. In case you want to pin against specific versions of your application, using the intermediate CA as a trust anchor is a good choice. Else you can pin against the root CA in which case different versions of your application can talk with each other, though you may not be able to launch them if they do not meet the minimum `SecurityVersion` specified in your original or updated manifest.

## Verifying the manifest

Establishing trust with the service mesh allows you to verify the deployed manifest in the second step.
To that end, MarbleRun exposes the endpoint `/manifest`.
Using the CLI, you can get the manifest's signature (its SHA256 hash) and compare it against your local version of the manifest which should have been provided to you by the operator.

Assuming the version of the manifest you want to verify is stored in a file called `manifest.json` on your local machine, you can verify it against the Coordinator's version with the following command:

```bash
marblerun manifest verify manifest.json $MARBLERUN
```
