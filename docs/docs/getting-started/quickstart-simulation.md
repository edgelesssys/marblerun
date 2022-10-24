# Quickstart simulation mode

## Step 1: Install the control plane onto your cluster

Install MarbleRun's *Coordinator* control plane by running:

```bash
marblerun install --simulation
```

The `marblerun install` command generates a Kubernetes manifest with all the necessary control plane resources.
This includes a deployment for the Coordinator and for MarbleRun's [admission controller.](../features/kubernetes-integration.md)
The simulation flag tells MarbleRun that real SGX hardware might not be present and the SGX-layer should be emulated.

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

## Step 2: Deploy the demo application

To get a feel for how MarbleRun would work for one of your services, you can install a demo application.
The emojivoto application is a standalone Kubernetes application that uses a mix of gRPC and HTTP calls to allow the users to vote on their favorite emojis.
Created as a demo application for the popular [Linkerd](https://linkerd.io) service mesh, we've made a confidential variant that uses a confidential service mesh for all gRPC and HTTP connections.
Clone the [demo application's repository]( https://github.com/edgelesssys/emojivoto.git) from GitHub by running:

```bash
git clone https://github.com/edgelesssys/emojivoto.git && cd emojivoto
```

### Step 2.1: Configure MarbleRun

MarbleRun guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON.
MarbleRun verifies the integrity of services, bootstraps them, and sets up encrypted connections between them.
The emojivoto demo already comes with a [manifest](https://github.com/edgelesssys/emojivoto/blob/main/tools/manifest.json), which you can deploy onto MarbleRun by running:

```bash
marblerun manifest set tools/manifest.json $MARBLERUN --insecure
```

Normally, the CLI will verify the Coordinators SGX quote every time it connects to the Coordinators REST interface.
Since we run MarbleRun in simulation mode, and therefore don't actually generate a quote, we use the `--insecure` flag to skip this verification.

You can check that the state of MarbleRun changed and is now ready to authenticate your services by running:

```bash
marblerun status $MARBLERUN --insecure
```

### Step 2.2: Deploy emojivoto

Finally, install the demo application onto your cluster.
Please make sure you have [Helm](https://helm.sh/docs/intro/install/) ("the package manager for Kubernetes") installed at least at Version v3.2.0.
Install emojivoto into the emojivoto namespace by running:

```bash
helm install -f ./kubernetes/nosgx_values.yaml emojivoto ./kubernetes --create-namespace -n emojivoto
```

## Step 3: Watch it run

You can now check the MarbleRun log and see the services being authenticated by the Coordinator.

```bash
kubectl -n marblerun logs -f -l edgeless.systems/control-plane-component=coordinator
```

Port forward the front-end web service to access it on your local machine by running:

```bash
kubectl -n emojivoto port-forward svc/web-svc 8443:443 --address 0.0.0.0
```

Now visit [https://localhost:8443](https://localhost:8443).
You'll be presented with a certificate warning because your browser by default doesn't trust certificates signed by MarbleRun.
You can ignore this error for now and proceed to the website.\
Voila! Your emoji votes have never been safer!

## That’s it 👏

Congratulations, you’re now a MarbleRun user! Here are some suggested next steps:

* Explore how [MarbleRun takes care of your secrets](../features/secrets-management.md)
* [Add your own service](../workflows/add-service.md) to MarbleRun
* Learn more about [MarbleRun’s architecture](../getting-started/concepts.md)
* Chat with us on [Discord](https://discord.gg/rH8QTH56JN)
* Try out the full demo on [GitHub](https://github.com/edgelesssys/emojivoto)

Welcome to the MarbleRun community!
