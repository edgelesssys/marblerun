# Quickstart

## Step 0: Setup
Before we can do anything, we need to ensure you have access to a Kubernetes cluster, and a functioning kubectl command on your local machine. (One easy option is to run Kubernetes on your local machine. We suggest [Docker Desktop](https://www.docker.com/products/docker-desktop) or [Minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/), but [there are many options](https://kubernetes.io/docs/setup/).)

When ready, make sure you're running a recent version of Kubernetes with:

```bash
kubectl version --short
```

## Step 1: Install Coordinator onto the cluster

Deploy with [helm](https://helm.sh/docs/intro/install/)

```bash
helm repo add edg-mesh https://helm.edgeless.systems/stable
helm repo update
```

* If your deploying on a cluster with nodes that support SGX1+FLC (e.g. AKS or minikube + Azure Standard_DC*s)

  ```bash
  helm install  edg-mesh-coordinator edg-mesh/coordinator --create-namespace edg-mesh
  ```

* Otherwise

  ```bash
  helm install edg-mesh-coordinator edg-mesh/coordinator --create-namespace edg-mesh --set coordinator.resources=null --set coordinator.OE_SIMULATION=1 --set tolerations=null
  ```

## Step 2: Pull the demo application

```bash
git clone https://github.com/edgelesssys/emojivoto.git && cd emojivoto
```


## Step 3: Establish Trust to the Coordinator

1. Pull the configuration and build the manifest

    ```bash
    tools/pull_manifest.sh
    ```

1. Get the Coordinator's address and set the DNS

    ```bash
    . tools/configure_dns.sh
    ```

1. Install the Edgeless Remote Attestation Tool
    1. Check [requirements](https://github.com/edgelesssys/era#requirements)
    2. See [install](https://github.com/edgelesssys/era#install)

1. Verify the Quote and get the Mesh's Root-Certificate
    * If you're running on a cluster with nodes that support SGX1+FLC

        ```bash
        era -c mesh.config -h $EDG_COORDINATOR_ADDR -o mesh.crt
        ```

    * Otherwise

        ```bash
        era -skip-quote -c mesh.config -h $EDG_COORDINATOR_ADDR -o mesh.crt
        ```

## Step 4: Set the Manifest

```bash
curl --silent --cacert mesh.crt -X POST -H  "Content-Type: application/json" --data-binary @tools/manifest.json "https://$EDG_COORDINATOR_SVC/manifest"
```

## Step 5: Deploy the demo application

* If your deploying on a cluster with nodes that support SGX1+FLC (e.g. AKS or minikube + Azure Standard_DC*s)

  ```bash
  helm install -f ./kubernetes/sgx_values.yaml emojivoto ./kubernetes -n emojivoto
  ```

* Otherwise

  ```bash
  helm install -f ./kubernetes/nosgx_values.yaml emojivoto ./kubernetes -n emojivoto
  ```

## Step 6: Watch it run

```bash
minikube -n emojivoto service web-svc
#Optional
sudo kubectl -n emojivoto port-forward svc/web-svc 443:443 --address 0.0.0.0
```

* Browse to [https://localhost:30001](https://localhost:30001) or [https://localhost](https://localhost) depending on your port-forwarding choice above.

* Notes on DNS: If your running emojivoto on a remote machine you can add the machine's DNS name to the emojivoto certificate (e.g. `emojivoto.example.org`):

  * Open the `kubernetes/sgx_values.yaml` or `kubernetes/nosgx_values.yaml` file depending on your type of deployment

  * Add your DNS name to the `hosts` field: 

    * `hosts: "emojivoto.example.org,localhost,web-svc,web-svc.emojivoto,web-svc.emojivoto.svc.cluster.local"`

  * You need to apply your changes with:

    * If your using `kubernetes/sgx_values.yaml` for your deployment:

        ```bash
        helm upgrade -f ./kubernetes/sgx_values.yaml emojivoto ./kubernetes -n emojivoto
        ```

    * Otherwise:

        ```bash
        helm upgrade -f ./kubernetes/nosgx_values.yaml emojivoto ./kubernetes -n emojivoto
        ```

Browse to `localhost:443`.
Optionally, you can import the trusted root certificate `mesh.crt` in your browser.