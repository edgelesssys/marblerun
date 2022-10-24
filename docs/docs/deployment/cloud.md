# Cloud deployment

This guide walks you through setting up MarbleRun on different CSP offerings individually.

## Azure confidential computing VMs

[Azure confidential computing services](https://azure.microsoft.com/en-us/solutions/confidential-compute/) provide access to VMs with Intel SGX enabled in [DCsv2 VM instances](https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series).
The description below uses a VM running Ubuntu 18.04.

### Prerequisites

* [Update and install EGo](https://github.com/edgelesssys/ego#install)
* [Update and install the Azure DCAP client](https://docs.microsoft.com/en-us/azure/confidential-computing/quick-create-portal#3-install-the-intel-and-open-enclave-packages-and-dependencies)

### Deploy MarbleRun

You can run MarbleRun standalone on your Azure DCsv2 VM, see our [standalone guide](deployment/standalone.md).
Alternatively, you can install a Kubernetes cluster, probably the simplest option would be [minikube](https://minikube.sigs.k8s.io/docs/start/), see our [Kubernetes guide](deployment/kubernetes.md) on how to install MarbleRun in minikube.

## Alibaba Cloud Elastic Compute Service

With 7th generation [security-enhanced ECS instances](https://www.alibabacloud.com/help/doc-detail/207734.htm) users can try out and use Intel SGX on Alibaba Cloud.
Currently, security-enhanced instances are only available as part of an invitational preview.

The description below uses a VM running Ubuntu 18.04.

### Prerequisites

1. Install Intel DCAP Quote Provider Library

    Add the Intel SGX APT repository:
    ```bash
    wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
    echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main' | sudo tee /etc/apt/sources.list.d/intel-sgx.list
    ```

    Download and install the QPL:
    ```bash
    sudo apt update
    sudo apt install libsgx-dcap-default-qpl
    ```

1. Set configuration for Alibaba Cloud SGX remote attestation service

    Alibaba Cloud provides a PCCS for remote attestation, deployed on a per-region basis. For optimal stability it's recommended to access the service in your instance's region.
    The configuration is set in `/etc/sgx_default_qcnl.conf`.

    * If your instance is assigned a public IP address, change the configuration to the following, where `[Region-ID]` is the ID of your instance's region:
        ```
        PCCS_URL=https://sgx-dcap-server.[Region-ID].aliyuncs.com/sgx/certification/v3/
        USE_SECURE_CERT=TRUE
        ```

    * If your instance is in a virtual private cloud and has only internal IP addresses, change the configuration to the following, where `[Region-ID]` is the ID of your instance's region:
        ```
        PCCS_URL=https://sgx-dcap-server-vpc.[Region-ID].aliyuncs.com/sgx/certification/v3/
        USE_SECURE_CERT=TRUE
        ```

    ?> Currently, the Alibaba Cloud SGX remote attestation service is only supported within [mainland China regions](https://www.alibabacloud.com/help/doc-detail/40654.htm#concept-2459516)

1. [Update and install EGo](https://github.com/edgelesssys/ego#install)

### Deploy MarbleRun

You can run MarbleRun standalone on your Alibaba Cloud ECS VM, see our [standalone guide](deployment/standalone.md).
Alternatively, you can install a Kubernetes cluster, probably the simplest option would be [minikube](https://minikube.sigs.k8s.io/docs/start/), see our [Kubernetes guide](deployment/kubernetes.md) on how to install MarbleRun in minikube.

## Azure Kubernetes Services (AKS)

Azure Kubernetes Service (AKS) offers a popular deployment technique relying on
Azure's cloud resources. AKS hosts Kubernetes pods in Azure confidential compute
VMs and exposes the underlying confidential compute hardware.

### Prerequisites

Follow the instructions on the [AKS Confidential Computing Quick Start guide](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-enclave-nodes-aks-get-started)
to provision an AKS cluster with Intel SGX enabled worker nodes.

### Deploy MarbleRun

See our [Kubernetes guide](deployment/kubernetes.md) on how to install MarbleRun in your AKS cluster.
