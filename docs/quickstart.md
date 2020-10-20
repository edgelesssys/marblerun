# Quickstart

## Step 0: Setup
Before we can do anything, we need to ensure you have access to a Kubernetes cluster, and a functioning kubectl command on your local machine. (One easy option is to run Kubernetes on your local machine. We suggest [Docker Desktop](https://www.docker.com/products/docker-desktop) or [Minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/), but [there are many options](https://kubernetes.io/docs/setup/).)

When ready, make sure you're running a recent version of Kubernetes with:

```bash
kubectl version --short
```

## Step 1: Install Coordinator onto the cluster

```bash
curl -sL https://github.com/edgelesssys/emojivoto/blob/master/kubernetes/coordinator.yml \
  | kubectl apply -f -
```

## Step 2: Pull the demo application

```bash
git clone https://github.com/edgelesssys/emojivoto.git && cd emojivoto
tools/pull_manifest.sh
. tools/configure_dns.sh
go install github.com/edgelesssys/era/cmd/era
```

## Step 3: Establish Trust to the Coordinator

```bash
era -c mesh.config -h $EDG_COORDINATOR_ADDR -o mesh.crt
```

## Step 4: Set the Manifest

```bash
curl --silent --cacert mesh.crt -X POST -H  "Content-Type: application/json" --data-binary @tools/manifest.json "https://$EDG_COORDINATOR_SVC/manifest"
```

## Step 5: Deploy the app

```bash
kubectl apply -f kubernetes/
```

## Step 6: Watch it run

```bash
sudo kubectl -n emojivoto port-forward svc/web-svc 443:443 --address 0.0.0.0
```

Browse to `localhost:443`.
Optionally, you can import the trusted root certificate `mesh.crt` in your browser.