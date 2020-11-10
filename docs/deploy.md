# Deploy Mesh to your cluster

## Before you begin

This article assumes that you have an existing AKS cluster. If you need an AKS cluster, see the AKS quickstart [using the Azure CLI](https://docs.microsoft.com/en-us/azure/aks/kubernetes-walkthrough) or using the [Azure portal](https://docs.microsoft.com/en-us/azure/aks/kubernetes-walkthrough-portal).
Alternatively, you can deploy with [minikube](https://minikube.sigs.k8s.io/docs/start/)

This article uses [Helm 3](https://helm.sh/) to install Edgeless Mesh. Make sure that you are using the latest release of Helm and have access to the Edgeless Mesh Helm repositories. For upgrade instructions, see the [Helm install docs](https://docs.helm.sh/using_helm/#installing-helm). For more information on configuring and using Helm, see [Install applications with Helm in Azure Kubernetes Service (AKS)](https://docs.microsoft.com/en-us/azure/aks/kubernetes-helm).

## Adding Edgeless Mesh's Helm repository

```bash
helm repo add edgeless https://helm.edgeless.systems
helm repo update
```

## Installing the chart

* If your deploying on a cluster with nodes that support SGX1+FLC (e.g. AKS or minikube + Azure Standard_DC*s)

    Update the hostname with your cluster's FQDN.

    ```bash
    helm install  marblerun-coordinator edgeless/marblerun-coordinator --create-namespace --namespace marblerun --set coordinator.hostname=mycluster.uksouth.cloudapp.azure.com
    ```

* Otherwise

    Update the hostname with your cluster's FQDN.

    ```bash
    helm install marblerun-coordinator edgeless/marblerun-coordinator --create-namespace --namespace marblerun --set coordinator.resources=null --set coordinator.simulation=1 --set tolerations=null --set coordinator.hostname=mycluster.uksouth.cloudapp.azure.com
    ```

## DNS for the Client-API on Azure Kubernetes Service (AKS)

This explains how to configure the DNS for the Edgless Mesh Client-API when running on a AKS cluster.

### Configure FQDN for the coordinators' IP address

```bash
# Public IP address of your coordinator-client-api service
IP="MY_EXTERNAL_IP"

# Name to associate with public IP address
DNSNAME="marblerun"

# Get the resource-id of the public ip
PUBLICIPID=$(az network public-ip list --query "[?ipAddress!=null]|[?contains(ipAddress, '$IP')].[id]" --output tsv)

# Update public ip address with DNS name
az network public-ip update --ids $PUBLICIPID --dns-name $DNSNAME

# Display the FQDN
az network public-ip show --ids $PUBLICIPID --query "[dnsSettings.fqdn]" --output tsv
```

### Test the DNS configuration

Use curl to test that the DNS was configured correctly. Update the hostname with the DNS name you created.

```bash
curl -k https://marblerun.uksouth.cloudapp.azure.com/status
```
