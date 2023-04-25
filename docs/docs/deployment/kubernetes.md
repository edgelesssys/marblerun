# Kubernetes MarbleRun deployment

This guide walks you through setting up MarbleRun in your Kubernetes cluster.

The Kubernetes deployment is managed through the use of a [Helm chart](https://helm.sh/), which can be found in our [source repository](https://github.com/edgelesssys/marblerun/tree/master/charts) and installed via our [Helm repository.](https://helm.edgeless.systems)
The installation consists of a deployment for the Coordinator and an admission controller.
For more details see our section on [Kubernetes Integration](../features/kubernetes-integration.md).

## Prerequisites

### SGX device plugin on Kubernetes

Kubernetes manages hardware resources like Intel SGX through its [device plugin framework](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/).
The SGX device plugin can either be deployed manually or as a DaemonSet in the cluster. Different vendors provide open-source device plugins for SGX:

* [Intel](https://intel.github.io/intel-device-plugins-for-kubernetes/cmd/sgx_plugin/README.html)
* [Azure](https://github.com/Azure/aks-engine/blob/master/docs/topics/sgx.md#deploying-the-sgx-device-plugin)
* [Alibaba Cloud](https://github.com/AliyunContainerService/sgx-device-plugin)

:::info

If you are using a CC-enlightened, managed Kubernetes cluster, you will usually already have an SGX device plugin installed.
For example, creating a confidential computing cluster on AKS has a pre-configured SGX device plugin.

:::

### Manually deploying an SGX device plugin

For different reasons, you may want to deploy the device plugin manually. Intel provides [a guide](https://intel.github.io/intel-device-plugins-for-kubernetes/cmd/sgx_plugin/README.html#installation) to install their SGX plugin.
In any case, you will need to adjust your deployments to request the SGX resources provided by the plugin:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: oe-deployment
spec:
  selector:
    matchLabels:
      app: oe-app
  replicas: 1
  template:
    metadata:
      labels:
        app: oe-app
    spec:
      tolerations:
      - key: sgx.intel.com/epc
        operator: Exists
        effect: NoSchedule
      containers:
      - name: <image_name>
        image: <image_reference>
        command: <exec>
        resources:
          limits:
            sgx.intel.com/epc: 10Mi
            sgx.intel.com/enclave: 1
            sgx.intel.com/provision: 1
```

Note, that every plugin uses its own way of injecting SGX resources into deployments. Please refer to the documentation for your plugin of choice. This is an example of the Intel plugin.

MarbleRun supports [automatic injection](../features/kubernetes-integration.md) of those values for a selection of popular plugins:

* [Intel](https://intel.github.io/intel-device-plugins-for-kubernetes/cmd/sgx_plugin/README.html) using `sgx.intel.com/epc`, `sgx.intel.com/enclave`, and `sgx.intel.com/provision`
* [Azure](https://github.com/Azure/aks-engine/blob/master/docs/topics/sgx.md#deploying-the-sgx-device-plugin) using `kubernetes.azure.com/sgx_epc_mem_in_MiB`
* [Alibaba Cloud](https://github.com/AliyunContainerService/sgx-device-plugin) using `alibabacloud.com/sgx_epc_MiB`
* You can use the `--resource-key` flag, during installation with the CLI, to declare your own SGX resource key for injection

:::tip

If you are using a different plugin please let us know, so we can add support!

:::

### Out-of-process attestation

Intel SGX supports two modes for obtaining remote attestation quotes:

* In-process: The software generating the quote is part of the enclave application
* Out-of-process: The software generating the quote isn't part of the actual enclave application. This requires the Intel SGX Architectural Enclave Service Manager (AESM) to run on the system

While Marbles built with [Ego](../building-services/ego.md) perform in-process attestation, other frameworks, such as [Gramine](../building-services/gramine.md), use out-of-process attestation.
If your confidential application uses out-of-process attestation, you will need to expose the AESM device to your container.

You can follow [the AKS guide](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-addon) to make your deployments able to use AESM for quote generation. Note, that in this case, your Kubernetes nodes need the AESM service installed. See the [Intel installation guide](https://download.01.org/intel-sgx/sgx-linux/2.12/docs/Intel_SGX_Installation_Guide_Linux_2.12_Open_Source.pdf) for more information.

## Option 1: Install with the MarbleRun CLI

Use MarbleRun's [CLI](../reference/cli.md) that facilitates the administrative tasks.
You can install MarbleRun using the CLI as follows:

* For a cluster with SGX support:

    ```bash
    marblerun install --domain=mycluster.uksouth.cloudapp.azure.com
    ```

* For a cluster without SGX support:

    ```bash
    marblerun install --domain=mycluster.uksouth.cloudapp.azure.com --simulation
    ```

This command will pull the latest Helm chart from [our repository](https:/helm.edgeless.systems) and manages the installation of said chart.

By default `--domain` is set to `localhost`.
The domain is used as the CommonName in the Coordinator's TLS certificate.
This certificate is used for the HTTPS communication of the Coordinator's client API.
The HTTPS endpoint is exposed via a [Kubernetes ClusterIP Service](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types).
If you plan on exposing the endpoint on a public IP, make sure that the domain set via `--domain` matches the one configured for the public IPs provisioned in your cluster.
On Azure, you can [use a static public IP address with the Azure Kubernetes Service (AKS) load balancer](https://docs.microsoft.com/en-us/azure/aks/static-ip#create-a-static-ip-address).
The client API can be used by users/clients of your application to obtain one concise remote attestation statement for your cluster.

The Coordinator is now in a pending state, waiting for a manifest.
See the [how to add a service](../workflows/add-service.md) documentation for more information on how to create and set a manifest.

## Option 2: Install with Helm

Make sure that you are using the latest release of Helm and have access to the MarbleRun Helm repositories. For upgrade instructions, see the [Helm install docs](https://docs.helm.sh/using_helm/#installing-helm). For more information on configuring and using Helm, see [Install applications with Helm in Azure Kubernetes Service (AKS)](https://docs.microsoft.com/en-us/azure/aks/kubernetes-helm).

### Adding MarbleRun's Helm repository

```bash
helm repo add edgeless https://helm.edgeless.systems/stable
helm repo update
```

### Installing the chart

Note that installing MarbleRun with the [marble-injector webhook](../features/kubernetes-integration.md) enabled using Helm requires [cert-manager](https://cert-manager.io/docs/) to be installed in your cluster.
Review the `values.yaml` file of the chart for a full list of available configuration options.

Update the hostname with your cluster's FQDN.

* For a cluster with SGX support:

    ```bash
    helm install marblerun edgeless/marblerun \
        --create-namespace \
        -n marblerun \
        --set coordinator.hostname=mycluster.uksouth.cloudapp.azure.com \
        --set marbleInjector.start=true \
        --set marbleInjector.useCertManager=true
    ```

* For a cluster without SGX support:

    ```bash
    helm install marblerun edgeless/marblerun \
        --create-namespace \
        -n marblerun \
        --set coordinator.resources=null \
        --set coordinator.simulation=1 \
        --set tolerations=null \
        --set coordinator.hostname=mycluster.uksouth.cloudapp.azure.com \
        --set marbleInjector.start=true \
        --set marbleInjector.useCertManager=true
    ```

By default `coordinator.hostname` is set to `localhost`.
The domain is used as the CommonName in the Coordinator's TLS certificate.
This certificate is used for the HTTPS communication of the Coordinator's client API.
The HTTPS endpoint is exposed via a [Kubernetes ClusterIP Service](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types).
If you plan on exposing the endpoint on a public IP, make sure that the domain set via `--domain` matches the one configured for the public IPs provisioned in your cluster.
On Azure, you can [use a static public IP address with the Azure Kubernetes Service (AKS) load balancer](https://docs.microsoft.com/en-us/azure/aks/static-ip#create-a-static-ip-address).
The client API can be used by users/clients of your application to obtain one concise remote attestation statement for your cluster.

The Coordinator is now in a pending state, waiting for a manifest.
See the [how to add a service](../workflows/add-service.md) documentation for more information on how to create and set a manifest.

## (Optional) Exposing the client API

The Coordinator creates a [`ClusterIP`](https://kubernetes.io/docs/concepts/services-networking/service/#publishing-services-service-types) service called `coordinator-client-api` exposing the client API on the default port 4433.
Depending on your deployment type you may want to deploy an Ingress Gateway forwarding the traffic or create a [`LoadBalancer`](https://kubernetes.io/docs/concepts/services-networking/service/#loadbalancer) service to expose the endpoint on a public IP.

You can also use `kubectl` to forward the port to your local system:

```bash
kubectl -n marblerun port-forward svc/coordinator-client-api 4433:4433 --address localhost
```

### Ingress/Gateway configuration

If you're using an ingress-controller or gateway for managing access to the `coordinator-client-api` service, make sure you're enabling SNI for your TLS connections.

* For the nginx ingress controller add the [`nginx.ingress.kubernetes.io/ssl-passthrough`](https://kubernetes.github.io/ingress-nginx/user-guide/nginx-configuration/annotations/#ssl-passthrough) annotation.
* For Istio Gateways set the [tls-mode PASSTHROUGH](https://istio.io/latest/docs/tasks/traffic-management/ingress/ingress-sni-passthrough/#configure-an-ingress-gateway)

## DCAP configuration

By default the Coordinator will generate its quote using the [Azure-DCAP-Client](https://github.com/microsoft/Azure-DCAP-Client). If you choose to use this, no additional steps are required.
If you want to use a PCCS other than Azure's you can do so by setting the [necessary configuration](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/qpl/README.md#configuration) during installation:

* Using the CLI

  ```bash
  marblerun install --dcap-qpl intel --dcap-pccs-url <PCCS_URL> --dcap-secure-cert <TRUE/FALSE>
  ```

* Using Helm

  ```bash
  helm install marblerun edgeless/marblerun \
        --create-namespace \
        -n marblerun \
        --set coordinator.hostname=mycluster.uksouth.cloudapp.azure.com \
        --set dcap.qpl=intel \
        --set dcap.pccsUrl=<PCCS_URL> \
        --set dcap.useSecureCert=<TRUE/FALSE>
  ```
