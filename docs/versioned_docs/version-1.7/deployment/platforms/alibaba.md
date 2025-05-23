# Alibaba Cloud MarbleRun deployment

## Alibaba Cloud Container Service for Kubernetes (ACK)

Alibaba Cloud Container Service for Kubernetes (ACK) offers a popular deployment technique relying on Alibaba's cloud resources.
[ACK hosts Kubernetes pods in SGX-capable Alibaba VMs](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/tee-based-confidential-computing) and exposes the underlying SGX hardware.

### Prerequisites

* Follow the instructions on the [ACK Confidential Computing Quick Start guide](https://www.alibabacloud.com/help/en/ack/ack-managed-and-ack-dedicated/user-guide/create-an-ack-managed-cluster-for-confidential-computing) to provision an ACK cluster with Intel SGX-enabled worker nodes.

### Deploy MarbleRun

See the [Kubernetes guide](../kubernetes.md) on installing MarbleRun in your ACK cluster.

## Alibaba Cloud Elastic Compute Service

With 7th-generation [security-enhanced ECS instances](https://www.alibabacloud.com/help/en/ecs/user-guide/overview-25), users can use Intel SGX on Alibaba Cloud.
You can follow the guide for creating a [g7t, c7t, or r7t](https://www.alibabacloud.com/help/en/ecs/user-guide/create-a-security-enhanced-instance) instance.

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

    Alibaba Cloud provides a PCCS for remote attestation deployed per region. For optimal stability, accessing the service in your instance's region is recommended.
    The configuration is set in `/etc/sgx_default_qcnl.conf`.

    * If your instance is assigned a public IP address, change the configuration to the following, where `[Region-ID]` is the ID of your instance's region:

        ```
        PCCS_URL=https://sgx-dcap-server.[Region-ID].aliyuncs.com/sgx/certification/v4/
        USE_SECURE_CERT=TRUE
        ```

    * If your instance is in a virtual private cloud and has only internal IP addresses, change the configuration to the following, where `[Region-ID]` is the ID of your instance's region:

        ```
        PCCS_URL=https://sgx-dcap-server-vpc.[Region-ID].aliyuncs.com/sgx/certification/v4/
        USE_SECURE_CERT=TRUE
        ```

    :::note

    Currently, the Alibaba Cloud SGX remote attestation service is only supported within [mainland China regions, Singapore, and Indonesia](https://www.alibabacloud.com/help/en/ecs/user-guide/build-an-sgx-encrypted-computing-environment)

    :::

1. [Update and install EGo](https://github.com/edgelesssys/ego#install)

### Deploy MarbleRun

You can run MarbleRun standalone on your Alibaba Cloud ECS VM. See the [standalone guide](../standalone.md).
Alternatively, you can install a Kubernetes cluster. Probably the simplest option would be [minikube](https://minikube.sigs.k8s.io/docs/start/). See the [Kubernetes guide](../kubernetes.md) on how to install MarbleRun in minikube.
