# Installation and setup

In this guide, you will install MarbleRun into your Kubernetes cluster and deploy a sample confidential application to demonstrate the capabilities of MarbleRun.

Installing MarbleRun is easy. First, you will install the CLI (command-line interface) onto your local machine. Using this CLI, you’ll then install the control plane onto your Kubernetes cluster.
Finally, you will add your services and set up a corresponding manifest.

## Prerequisites

Make sure the following requirements are met:

* Your machine is running Ubuntu 20.04 on an x86 (AMD64) CPU
* You have access to a Kubernetes cluster and kubectl installed and configured

Probably the easiest way to get started is to run Kubernetes on your local machine using [minikube](https://minikube.sigs.k8s.io/docs/start/). Please check our [prerequisites](../deployment/kubernetes.md#prerequisites) if you want to set up an SGX-enabled cluster. Another easy way is to use [Azure Kubernetes Service (AKS)](https://docs.microsoft.com/en-us/azure/aks/kubernetes-walkthrough-portal), which offers SGX-enabled nodes.

You can validate your setup by running the following:

```bash
kubectl version --short
```

You should see an output with both a Client Version and a Server Version component.
Now your cluster is ready and we’ll install the MarbleRun CLI.

## Install the MarbleRun CLI

If this is your first time running MarbleRun, you will need to download the MarbleRun command-line interface (CLI) onto your local machine. The CLI will allow you to interact with your MarbleRun deployment.

To install the CLI, run the following:

<Tabs groupId="user">
<TabItem value="current-user" label="For the current user">

```bash
wget -P ~/.local/bin https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
chmod +x ~/.local/bin/marblerun
```

</TabItem>
<TabItem value="global" label="Global install (requires root)">

```bash
sudo wget -O /usr/local/bin/marblerun https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
sudo chmod +x /usr/local/bin/marblerun
```

</TabItem>
</Tabs>

Once installed, verify the CLI is running correctly with the following:

```bash
marblerun
```

You can use the CLI to check if your cluster is configured to run SGX workloads:

```bash
marblerun precheck
```
