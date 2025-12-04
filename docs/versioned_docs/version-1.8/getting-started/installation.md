# Installation and setup

To install MarbleRun into your Kubernetes cluster and manage it, there's a dedicated command-line interface (CLI).
The following guides you through the steps of installing the CLI on your machine and the configuration required to verify the [Coordinator's attestation reports](../workflows/verification.md).

## Prerequisites

Make sure the following requirements are met:

* Your machine is running Linux on an x86-64 CPU
* You have access to a Kubernetes cluster and kubectl installed and configured

An easy way to get started is to run Kubernetes on your local machine using [minikube](https://minikube.sigs.k8s.io/docs/start/).
Check the [prerequisites](../deployment/kubernetes.md#prerequisites) if you want to set up an SGX-enabled cluster.
Another easy way is to use [Azure Kubernetes Service (AKS)](https://learn.microsoft.com/en-us/azure/aks/learn/quick-kubernetes-deploy-portal), which offers SGX-enabled nodes.

You can validate your setup by running the following:

```bash
kubectl version --short
```

You should see an output with both a Client Version and a Server Version component.
Now your cluster is ready and you can install the MarbleRun CLI.

## Install the MarbleRun CLI

CLI executables for different platforms are available at [GitHub](https://github.com/edgelesssys/marblerun/releases).
The CLI needs an SGX [quote provider](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/DCAP_ECDSA_Orientation.pdf) to verify attestation reports.

<Tabs groupId="platform">
<TabItem value="appimage" label="AppImage">

The AppImage runs on all x86-64 Linux distributions with glibc v2.29 or higher.
It includes the quote provider.
Install it with the following commands:

```bash
wget https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun-x86_64.AppImage
sudo install marblerun-x86_64.AppImage /usr/local/bin/marblerun
```

</TabItem>
<TabItem value="ub2004" label="Ubuntu 20.04">

Install the CLI and the quote provider with the following commands:

```bash
# install CLI
wget https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun-ubuntu-20.04
sudo install marblerun-ubuntu-20.04 /usr/local/bin/marblerun

# install quote provider
sudo mkdir -p /etc/apt/keyrings
wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
sudo apt update
sudo apt install libsgx-dcap-default-qpl
```

</TabItem>
<TabItem value="ub2204" label="Ubuntu 22.04">

Install the CLI and the quote provider with the following commands:

```bash
# install CLI
wget https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun-ubuntu-22.04
sudo install marblerun-ubuntu-22.04 /usr/local/bin/marblerun

# install quote provider
wget -qO- https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo tee /etc/apt/keyrings/intel-sgx-keyring.asc > /dev/null
echo "deb [signed-by=/etc/apt/keyrings/intel-sgx-keyring.asc arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu jammy main" | sudo tee /etc/apt/sources.list.d/intel-sgx.list
sudo apt update
sudo apt install libsgx-dcap-default-qpl
```

</TabItem>
</Tabs>

Once installed, verify the CLI is running correctly with the following:

```bash
marblerun
```

You can use the CLI to check if your cluster is configured to run SGX workloads:

```bash
marblerun precheck
```

## Configure the quote provider

The CLI uses the quote provider to retrieve collaterals required for verifying attestation reports.
Locate its configuration file at `/etc/sgx_default_qcnl.conf`.
If the file doesn't exist or is outdated, download it with the following command:

```bash
wget -qO- https://raw.githubusercontent.com/intel/SGXDataCenterAttestationPrimitives/master/QuoteGeneration/qcnl/linux/sgx_default_qcnl.conf | sudo tee /etc/sgx_default_qcnl.conf > /dev/null
```

You can configure the quote provider to get the collaterals from the Intel PCS, the PCCS of your cloud service provider (CSP), or your own PCCS.

### Intel PCS

Using the Intel PCS is the simplest and most generic way to get the collaterals, but it may be slower and less reliable than a PCCS.
Configure it by uncommenting the `"collateral_service"` key:

```json
  ,"collateral_service": "https://api.trustedservices.intel.com/sgx/certification/v4/"
```

### PCCS of your CSP

If you're running MarbleRun in the cloud, it's recommended to use the PCCS of your CSP.
Set the `"pccs_url"` value to the respective address:

* Azure: `https://global.acccache.azure.net/sgx/certification/v4/`

  See the [Azure documentation](https://learn.microsoft.com/en-us/azure/security/fundamentals/trusted-hardware-identity-management#how-do-i-use-intel-qpl-with-trusted-hardware-identity-management) for more information on configuring the quote provider.

* Alibaba: `https://sgx-dcap-server.[Region-ID].aliyuncs.com/sgx/certification/v4/`

  See the [Alibaba documentation](https://www.alibabacloud.com/help/en/ecs/user-guide/build-an-sgx-encrypted-computing-environment) for supported Region-ID values and more information on configuring the quote provider.

### Your own PCCS

If you're running MarbleRun on premises and have set up your own PCCS for quote generation, you can also use it for quote verification.
Set the `"pccs_url"` value to the address of your PCCS.

If your PCCS runs with a certificate not signed by a trusted CA, you need to set `"use_secure_cert"` to `false`.
This instructs the quote provider to accept a self-signed certificate of the PCCS.
It doesn't affect the security of the remote attestation process itself.
