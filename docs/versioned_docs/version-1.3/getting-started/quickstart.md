# First steps with MarbleRun

The following steps guide you through the process of deploying MarbleRun in your cluster and deploying a sample app. This example assumes that you have successfully [installed MarbleRun](./installation.md), and have access to a Kubernetes cluster.

A working SGX DCAP environment is required for MarbleRun. For ease of exploring and testing, we provide a simulation mode with `--simulation` that runs without SGX hardware.
Depending on your setup, you may follow the quickstart for SGX-enabled clusters. Alternatively, if your setup doesn't support SGX, you can follow the quickstart in simulation mode by selecting the respective tabs.

## Step 1: Install the control plane onto your cluster

Install MarbleRun's *Coordinator* control plane by running:

<Tabs groupId="mode">
<TabItem value="SGX" label="With SGX">

```bash
marblerun install
```

The `marblerun install` command generates a Kubernetes manifest with all the necessary control plane resources.
This includes a deployment for the Coordinator and for MarbleRun's [admission controller.](../features/kubernetes-integration.md)

</TabItem>
<TabItem value="Simulation" label="In simulation mode">

```bash
marblerun install --simulation
```

The `marblerun install` command generates a Kubernetes manifest with all the necessary control plane resources.
This includes a deployment for the Coordinator and for MarbleRun's [admission controller.](../features/kubernetes-integration.md)
The simulation flag tells MarbleRun that real SGX hardware might not be present and the SGX layer should be emulated.

</TabItem>
</Tabs>

Wait for the control plane to finish installing:

```bash
marblerun check
```

This command will wait until all components of MarbleRun are ready to be used or return an error after a timeout period is reached.

Port forward the Coordinator's Client API:

```bash
kubectl -n marblerun port-forward svc/coordinator-client-api 4433:4433 --address localhost >/dev/null &
export MARBLERUN=localhost:4433
```

## Step 2: Verify the Coordinator

After installing the Coordinator, we need to verify its integrity.
For this, we utilize SGX remote attestation and obtain the Coordinator's root certificate.

Verify the quote and get the Coordinator's root certificate

<Tabs groupId="mode">
<TabItem value="SGX" label="With SGX">

```bash
marblerun certificate root $MARBLERUN -o marblerun.crt
```

</TabItem>
<TabItem value="Simulation" label="In simulation mode">

```bash
marblerun certificate root $MARBLERUN -o marblerun.crt --insecure
```

The insecure flag tells MarbleRun that real SGX hardware might not be present and the quote verification should be omitted.

</TabItem>
</Tabs>

The CLI will obtain the Coordinator's remote attestation quote and verify it against the configuration on our [release page](https://github.com/edgelesssys/marblerun/releases/latest/download/coordinator-era.json).
The SGX quote proves the integrity of the Coordinator pod.
The CLI returns a certificate and stores it as `marblerun.crt` in your current directory.
The certificate is bound to the quote and can be used for future verification.
It can also be used as a root of trust for [authenticating your confidential applications](../features/attestation.md).

## Step 3: Deploy the demo application

To get a feel for how MarbleRun would work for one of your services, you can install a demo application.
The emojivoto application is a standalone Kubernetes application that uses a mix of gRPC and HTTP calls to allow users to vote on their favorite emojis.
Created as a demo application for the popular [Linkerd](https://linkerd.io) service mesh, we've made a confidential variant that uses a confidential service mesh for all gRPC and HTTP connections.
Clone the [demo application's repository](https://github.com/edgelesssys/emojivoto.git) from GitHub by running the following:

```bash
git clone https://github.com/edgelesssys/emojivoto.git && cd emojivoto
```

### Step 3.1: Configure MarbleRun

MarbleRun guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON.
MarbleRun verifies the integrity of services, bootstraps them, and sets up encrypted connections between them.
The emojivoto demo already comes with a [manifest](https://github.com/edgelesssys/emojivoto/blob/main/tools/manifest.json), which you can deploy onto MarbleRun by running the following:

<Tabs groupId="mode">
<TabItem value="SGX" label="With SGX">

```bash
marblerun manifest set tools/manifest.json $MARBLERUN
```

</TabItem>
<TabItem value="Simulation" label="In simulation mode">

```bash
marblerun manifest set tools/manifest.json $MARBLERUN --insecure
```

</TabItem>
</Tabs>

You can check that the state of MarbleRun has changed and is now ready to authenticate your services by running:

<Tabs groupId="mode">
<TabItem value="SGX" label="With SGX">

```bash
marblerun status $MARBLERUN
```

</TabItem>
<TabItem value="Simulation" label="In simulation mode">

```bash
marblerun status $MARBLERUN --insecure
```

</TabItem>
</Tabs>

### Step 3.2: Deploy emojivoto

Finally, install the demo application onto your cluster.
Please make sure you have [Helm](https://helm.sh/docs/intro/install/) ("the package manager for Kubernetes") installed at least at Version v3.2.0.
Install emojivoto into the emojivoto namespace by running:

<Tabs groupId="mode">
<TabItem value="SGX" label="With SGX">

```bash
helm install -f ./kubernetes/sgx_values.yaml emojivoto ./kubernetes --create-namespace -n emojivoto
```

</TabItem>
<TabItem value="Simulation" label="In simulation mode">

```bash
helm install -f ./kubernetes/nosgx_values.yaml emojivoto ./kubernetes --create-namespace -n emojivoto
```

</TabItem>
</Tabs>

## Step 4: Watch it run

You can now check the MarbleRun log and see the services being authenticated by the Coordinator.

```bash
kubectl -n marblerun logs -f -l edgeless.systems/control-plane-component=coordinator
```

Port forward the front-end web service to access it on your local machine by running:

```bash
kubectl -n emojivoto port-forward svc/web-svc 8443:443 --address 0.0.0.0
```

Now visit [https://localhost:8443](https://localhost:8443).
You'll be presented with a certificate warning because your browser, by default, doesn't trust certificates signed by MarbleRun.
You can ignore this error for now and proceed to the website.\
Voila! Your emoji votes have never been safer!

## That’s it 👏

Congratulations, you’re now a MarbleRun user! Here are some suggested next steps:

* Explore how [MarbleRun takes care of your secrets](../features/secrets-management.md)
* [Add your own service](../workflows/add-service.md) to MarbleRun
* Learn more about [MarbleRun’s architecture](../architecture/concepts.md)
* Chat with us on [Discord](https://discord.gg/rH8QTH56JN)
* Try out the full demo on [GitHub](https://github.com/edgelesssys/emojivoto)

Welcome to the MarbleRun community!
