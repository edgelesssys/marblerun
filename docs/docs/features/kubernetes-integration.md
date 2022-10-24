# Kubernetes integration

MarbleRun provides its data-plane configuration through Kubernetes resource definitions. For this, like regular service meshes, MarbleRun uses Kubernetes' [admission controllers](https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/#mutatingadmissionwebhook).

MarbleRun optionally injects [tolerations](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) and [resources](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/) for its SGX device plugin. See the [Kubernetes deployment](deployment/kubernetes.md#sgx-device-plugin-on-kubernetes) section for more information.

You can enable auto-injection of the data-plane configuration using Pod labels.

## The Marbletype label

In MarbleRun, Marbles (i.e, secure enclaves) are defined in the [manifest](workflows/define-manifest.md). You need to reference Marbles in your Kubernetes resource description as follows using the `marblerun/marbletype` label:

```javascript
{
    "Marbles": {
        "voting-svc": {
    // ...
```

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: voting
  namespace: emojivoto
  labels:
    app.kubernetes.io/name: voting
    app.kubernetes.io/part-of: emojivoto
    app.kubernetes.io/version: v1
    marblerun/marbletype: voting-svc
```

We use this label to map Kubernetes Pods to MarbleRun Marbles.
When you deploy your application with the `marblerun/marbletype` label, the Pod's creation is intercepted by MarbleRun.
It will then inject environment variables and SGX resources into the containers of the Pod based on the value of the label.
If the `marblerun/marbletype` label is missing, the Pod's injection is skipped.

## The Marblecontainer label

By default MarbleRun will inject environment variables and resource requests into all containers of the Pod.
You can use the `marblerun/marblecontainer=<ContainerName>` label to limit injection to the specified container.
This is useful if your configuration uses multiple containers in the same Pod, e.g. a sidecar proxy, and you wish to prevent non enclave containers taking up resources.

## The resource-injection label

To prevent MarbleRun from injecting SGX resource request, you can set the label `marblerun/resource-injection=disabled`.
Use this if you want to set your own SGX resource requests, or if you need to start a Marble in simulation mode without any SGX resources.

## Injected environment variables

The webhook will inject the following environment variables into each container of a pod:

* `EDG_MARBLE_TYPE`:  The value of the `marblerun/marbletype` label
* `EDG_MARBLE_COORDINATOR_ADDR`:  The address of the MarbleRun Coordinator running on the cluster
* `EDG_MARBLE_DNS_NAMES`:  DNS names of the pod derived from marbletype and namespace: `marbletype, marbletype.namespace, marbletype.namespace.svc.cluster.local`
* `EDG_MARBLE_UUID_FILE`:  The mounted UUID of the Marble

If an environment variable is already set before the webhook handles the creation request, the variable will not be overwritten and the custom value is used instead.
