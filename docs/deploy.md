# Deploy Mesh to your cluster

We provide a [helm](https://helm.sh/docs/intro/install/) chart for quick and easy deployment of Edgless Mesh.

## Adding Edgeless Mesh's Helm repository

```bash
helm repo add edg-mesh https://helm.edgeless.systems/stable
helm repo update
```

## Installing the chart

* If your deploying on a cluster with nodes that support SGX1+FLC (e.g. AKS or minikube + Azure Standard_DC*s)

```bash
helm install  edg-mesh-coordinator edg-mesh/coordinator --create-namespace edg-mesh
```

* Otherwise

```bash
helm install edg-mesh-coordinator edg-mesh/coordinator --create-namespace edg-mesh --set coordinator.resources=null --set coordinator.OE_SIMULATION=1 --set tolerations=null
```