# On-premises MarbleRun deployment

This guide walks you through setting up MarbleRun for your on-premises deployment.

## Prerequisites

### Hardware and firmware

#### CPU

To deploy MarbleRun with Intel SGX, the machine or VM has to support Intel SGX.
Particularly, MarbleRun requires support for the SGX Data Center Attestation Primitives (DCAP).
You can verify [if your CPU supports DCAP](https://www.intel.com/content/www/us/en/support/articles/000057420/software/intel-security-products.html).

For more information read this article on [detecting Intel Software Guard Extensions](https://software.intel.com/content/www/us/en/develop/articles/properly-detecting-intel-software-guard-extensions-in-your-applications.html) in your applications.

#### BIOS

BIOS support is required for Intel SGX to provide the capability to enable and configure the Intel SGX feature in the system.
Currently, most of the SGX capable systems have SGX disabled by default in the BIOS. This default setting might change but for now, you need to manually enable it if it's not already enabled.

#### Updates

As with any modern technology, Intel SGX has been affected by security vulnerabilities. Intel addresses these vulnerabilities by updating the microcode of CPUs, changing the hardware of new CPUs, and updating the system software. Each microcode update that patches an SGX vulnerability requires a BIOS update. During remote attestation, it's checked that the microcode of the CPU which is deployed by the BIOS is up to date. The microcode and platform enclaves are commonly called the platform `Trusted Computing Base (TCB)`.

If your BIOS/firmware is outdated, you will see errors as `Platform TCB (2) is not up-to-date (oe_result_t=OE_TCB_LEVEL_INVALID)` during remote attestation procedures.

#### Hypervisor

If you are using VMs for your MarbleRun deployment, you need to make sure your hypervisor has SGX enabled.
Most of the popular hypervisors support SGX:

* [QEMU/KVM](https://software.intel.com/content/www/us/en/develop/articles/virtualizing-intel-software-guard-extensions-with-kvm-and-qemu.html)
* [XEN](https://wiki.xenproject.org/wiki/Xen_and_Intel_Hardware-Assisted_Virtualization_Security)
* Hyper-V: Hyper-V will only expose SGX to Gen 2 VMs
* [VMWare vSphere](https://blogs.vmware.com/vsphere/2020/04/vsphere-7-vsgx-secure-enclaves.html)
* [ACRN](https://projectacrn.github.io/2.7/tutorials/sgx_virtualization.html)

#### Driver

You need to install the [DCAP SGX Driver](https://download.01.org/intel-sgx/sgx-dcap/1.11/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf).
Azure provides the instructions on [how to install this driver](https://docs.microsoft.com/en-us/azure/confidential-computing/quick-create-portal#2-install-the-intel-sgx-dcap-driver) that you can use for your on-premises machines.

### SGX Data Center Attestation Primitives (DCAP)

DCAP is the new attestation mechanism for SGX [replacing EPID](https://software.intel.com/content/www/us/en/develop/blogs/an-update-on-3rd-party-attestation.html).
You can find an overview of DCAP in the [official Intel docs](https://download.01.org/intel-sgx/sgx-dcap/1.11/linux/docs/DCAP_ECDSA_Orientation.pdf).
MarbleRun only supports DCAP and requires DCAP libraries installed and configured on your system.

From the perspective of MarbleRun and your workloads DCAP is accessed with a [Quote Generation Library (QGL)](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/README.md) and a [Quote Verification Library (QVL)](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/README.md) for generating and verifying quotes respectively.
The QGL and QVL libraries need to be configured to talk to a [Provisioning Certificate Caching Service (PCCS)](https://download.01.org/intel-sgx/sgx-dcap/1.11/linux/docs/DCAP_ECDSA_Orientation.pdf).
You currently have two options regarding PCCS for your on-premises machines and clusters:

1. Use a public PCCS service by configuring your QGL and QVL to point to the public endpoints. Currently, Azure and Alibaba Cloud provide such a service, but require using infrastructure by these providers to make full use of the service.

1. Run your own PCCS and expose it to your machine or cluster. See [Intel's demo reference implementation](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/pccs/README.md) and [design guide](https://download.01.org/intel-sgx/latest/dcap-latest/linux/docs/SGX_DCAP_Caching_Service_Design_Guide.pdf) for more information.

    Follow these steps to set up your machines for your PCCS:

      * Install the [DCAP client libraries](https://download.01.org/intel-sgx/sgx-dcap/1.11/linux/docs/Intel_SGX_SW_Installation_Guide_for_Linux.pdf)
      * Install a [configuration that points to your PCCS](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/qpl/README.md#configuration)

    The PCCS is a cache, so you need to make sure it stays up to date. In case your cache is outdated, you might see error messages as:

    ```bash
    coordinator-enclave.signed:mbedtls_x509_crt_verify failed with The CRL is expired (flags=0x20) (oe_result_t=OE_VERIFY_CRL_EXPIRED)
    ```

    You can inspect the Intel Root CA CRL of your PCCS:

    ```bash
    curl --insecure --request GET --url https://<YOUR_PCCS_DOMAIN>:<YOUR_PCCS_PORT>/sgx/certification/v3/rootcacrl > rootca.crl
    openssl crl -inform DER -text -noout -in rootca.crl
    ```

    You can refresh all SGX collaterals for your PCCS:

    ```bash
    curl --insecure --request GET -H "admin-token: <my password>" --url https://<YOUR_PCCS_DOMAIN>:<YOUR_PCCS_PORT>/sgx/certification/v3/refresh
    ```

    If refreshing CRL fails, you can manually delete the `pckcache.db` database (default location `/opt/intel/sgx-dcap-pccs/pckcache.db`) and restart your PCCS.

The docker image for the [MarbleRun Coordinator](https://github.com/edgelesssys/marblerun/pkgs/container/coordinator) comes with both the Azure-DCAP-Client and the default quote provider library by Intel.
To use your own PCCS, select the Intel library by starting a container with the environment variable `DCAP_LIBRARY=intel`, and mount the desired configuration to `/etc/sgx_default_qcnl.conf`.
Similarly, the [EGo image](https://github.com/orgs/edgelesssys/packages?repo_name=ego) comes preinstalled with both libraries.

## Deploy MarbleRun

You have made sure your hardware supports SGX, updated all firmware, installed the SGX driver, and configured DCAP on all your machines and VMs?
Great! Now it's time to install MarbleRun and get going.

You can either [use MarbleRun in standalone mode](deployment/standalone.md) or [install it in your Kubernetes cluster](deployment/kubernetes.md).
