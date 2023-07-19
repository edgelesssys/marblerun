## Azure Kubernetes Services (AKS)

Azure Kubernetes Service (AKS) offers a popular deployment technique relying on
Azure's cloud resources. AKS hosts Kubernetes pods in SGX-capabale Azure VMs and exposes the underlying SGX hardware.

### Prerequisites

* Follow the instructions on the [AKS Confidential Computing Quick Start guide](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-enclave-nodes-aks-get-started) to provision an AKS cluster with Intel SGX enabled worker nodes.
* [Update and install the Azure DCAP client](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal#install-azure-dcap-client)


### Deploy MarbleRun

See our [Kubernetes guide](../deployment/kubernetes.md) on how to install MarbleRun in your AKS cluster.

## Azure confidential computing VMs

[Azure confidential computing services](https://learn.microsoft.com/en-us/azure/confidential-computing/virtual-machine-solutions-sgx) provide access to VMs with Intel SGX enabled.
You can follow their [quickstart](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal) to create a [DCsv2](https://docs.microsoft.com/en-us/azure/virtual-machines/dcv2-series) (Coffee Lake) or [DCsv3](https://learn.microsoft.com/en-us/azure/virtual-machines/dcv3-series) (Ice Lake) VMs with Intel SGX enabled

The description below uses a VM running Ubuntu 18.04.

### Prerequisites

* [Update and install EGo](https://github.com/edgelesssys/ego#install)
* [Update and install the Azure DCAP client](https://learn.microsoft.com/en-us/azure/confidential-computing/quick-create-portal#install-azure-dcap-client)

### Deploy MarbleRun

You can run MarbleRun standalone on your Azure DCsv2/3 VM, see our [standalone guide](../deployment/standalone.md).
Alternatively, you can install a Kubernetes cluster, probably the simplest option would be [minikube](https://minikube.sigs.k8s.io/docs/start/), see our [Kubernetes guide](../deployment/kubernetes.md) on how to install MarbleRun in minikube.
