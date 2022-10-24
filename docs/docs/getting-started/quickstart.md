# Quickstart

In this guide, you will install MarbleRun into your Kubernetes cluster and deploy a sample confidential application to demonstrate the capabilities of MarbleRun.

Installing MarbleRun is easy. First, you will install the CLI (command-line interface) onto your local machine. Using this CLI, you’ll then install the control plane onto your Kubernetes cluster.
Finally, you will add your own services and set up a corresponding manifest.

!> A working SGX DCAP environment is required for MarbleRun to work. For the ease of exploring and testing we provide a simulation mode with `--simulation` that runs without SGX hardware.
Depending on your setup you may follow the [quickstart for SGX-enabled clusters](getting-started/quickstart-sgx.md). Alternatively, if your setup does not support SGX, you can follow the [quickstart in simulation mode](getting-started/quickstart-simulation.md).

## Step 0: Setup

First, ensure you have access to a Kubernetes cluster and kubectl installed and configured. Probably the easiest way to get started is to run Kubernetes on your local machine using [Minikube](https://minikube.sigs.k8s.io/docs/start/). Please check our [prerequisites](deployment/kubernetes.md#prerequisites) if you want to setup an SGX-enabled cluster. Another easy way is to use [Azure Kubernetes Service (AKS)](https://docs.microsoft.com/en-us/azure/aks/kubernetes-walkthrough-portal), which offers SGX-enabled nodes.

You can validate your setup by running:

```bash
kubectl version --short
```

You should see an output with both a Client Version and Server Version component.
Now your cluster is ready and we’ll install the MarbleRun CLI.

## Step 0.5: Install the CLI

If this is your first time running MarbleRun, you will need to download the MarbleRun command-line interface (CLI) onto your local machine. The CLI will allow you to interact with your MarbleRun deployment.

To install the CLI, run:

### For the current user

```bash
wget -P ~/.local/bin https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
chmod +x ~/.local/bin/marblerun
```

### Global install (requires root)

```bash
sudo wget -O /usr/local/bin/marblerun https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
sudo chmod +x /usr/local/bin/marblerun
```

Once installed, verify the CLI is running correctly with:

```bash
marblerun
```

You can use the CLI to check if your cluster is configured to run SGX workloads:

```bash
marblerun precheck
```

If your cluster supports SGX, you can follow the [quickstart for clusters with SGX support.](getting-started/quickstart-sgx.md) \
Otherwise, please follow the [quickstart in simulation mode.](getting-started/quickstart-simulation.md)
