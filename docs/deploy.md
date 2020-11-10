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

    ```bash
    helm install  edg-mesh-coordinator edgeless/coordinator --create-namespace --namespace edg-mesh
    ```

* Otherwise

    ```bash
    helm install edg-mesh-coordinator edgeless/coordinator --create-namespace --namespace edg-mesh --set coordinator.resources=null --set coordinator.simulation=1 --set tolerations=null
    ```

## Create an Ingress Controller for the Client-API on Azure Kubernetes Service (AKS)

This explains how to install the NGINX ingress controller and how to configure it to expose the Edgless Mesh Client-API.

### Create an ingress controller

```bash
# Create a namespace for your ingress resources
kubectl create namespace ingress-basic

# Add the ingress-nginx repository
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo update

# Use Helm to deploy an NGINX ingress controller
helm install nginx-ingress ingress-nginx/ingress-nginx \
    --namespace ingress-basic \
    --set controller.replicaCount=2 \
    --set controller.nodeSelector."beta\.kubernetes\.io/os"=linux \
    --set defaultBackend.nodeSelector."beta\.kubernetes\.io/os"=linux
```

During the installation, an Azure public IP address is created for the ingress controller. This public IP address is static for the life-span of the ingress controller. If you delete the ingress controller, the public IP address assignment is lost.

To get the public IP address, use the kubectl get service command. It takes a few minutes for the IP address to be assigned to the service.

```bash
$ kubectl --namespace ingress-basic get services -o wide -w nginx-ingress-ingress-nginx-controller
NAME                                     TYPE           CLUSTER-IP    EXTERNAL-IP     PORT(S)                      AGE   SELECTOR
nginx-ingress-ingress-nginx-controller   LoadBalancer   10.0.161.24   20.49.228.141   80:30736/TCP,443:32504/TCP   56s   app.kubernetes.io/component=controller,app.kubernetes.io/instance=nginx-ingress,app.kubernetes.io/name=ingress-nginx
```


### Configure FQDN for the ingress controller's IP address

```bash
# Public IP address of your ingress controller
IP="MY_EXTERNAL_IP"

# Name to associate with public IP address
DNSNAME="demo-aks-ingress"

# Get the resource-id of the public ip
PUBLICIPID=$(az network public-ip list --query "[?ipAddress!=null]|[?contains(ipAddress, '$IP')].[id]" --output tsv)

# Update public ip address with DNS name
az network public-ip update --ids $PUBLICIPID --dns-name $DNSNAME

# Display the FQDN
az network public-ip show --ids $PUBLICIPID --query "[dnsSettings.fqdn]" --output tsv
```

### Create an ingress route

Create a file named edg-mesh-ingress.yaml using below example YAML. Update the hosts and host to the DNS name you created in a previous step.

```json
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
annotations:
    kubernetes.io/ingress.class: nginx
    nginx.ingress.kubernetes.io/backend-protocol: "HTTPS"
name: edg-mesh-ingress
spec:
rules:
    - host: mycluster.uksouth.cloudapp.azure.com
    http:
        paths:
        - backend:
            serviceName: coordinator-client-api
            servicePort: 25555
            path: /manifest
        - backend:
            serviceName: coordinator-client-api
            servicePort: 25555
            path: /status
        - backend:
            serviceName: coordinator-client-api
            servicePort: 25555
            path: /quote
```

Create the ingress resource using the kubectl apply command.

```bash
kubectl apply -f edg-mesh-ingress.yaml --namespace edg-mesh
```

### Test the ingress configuration

Use curl to test that ingress was configured correctly. Update the hostname with the DNS name you created.

```bash
curl -k https://mycluster.uksouth.cloudapp.azure.com/status
```
