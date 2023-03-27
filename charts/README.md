# MarbleRun helm charts

## Documentation

See the [Getting Started Guide](https://docs.edgeless.systems/marblerun/getting-started/quickstart) to set up a distributed confidential-computing app in a few simple steps.
For more comprehensive documentation, start with the [docs](https://docs.edgeless.systems/marblerun).

## Add Repository (stable)

```bash
helm repo add edgeless https://helm.edgeless.systems/stable
helm repo update
```

## Install Packages (stable)

* If you are deploying on a cluster with nodes that support SGX1+FLC (e.g. AKS or minikube + Azure Standard_DC*s)

    ```bash
    helm install  marblerun edgeless/marblerun --create-namespace  --namespace marblerun
    ```

* Otherwise

    ```bash
    helm install marblerun edgeless/marblerun --create-namespace --namespace marblerun --set coordinator.resources=null --set coordinator.simulation=1 --set tolerations=null
    ```

## Configuration

The following table lists the configurable parameters of the marblerun chart and
their default values.

| Parameter                                    | Type           | Description    | Default                              |
|:---------------------------------------------|:---------------|:---------------|:-------------------------------------|
| `coordinator.clientServerHost`               | string         | Hostname of the client-api server | `"0.0.0.0"` |
| `coordinator.clientServerPort`               | int            | Port of the client-api server configuration | `4433` |
| `coordinator.hostname`                       | string         | DNS-Names for the coordinator certificate | `"localhost"` |
| `coordinator.image`                          | string         | Name of the coordinator container image | `"coordinator"` |
| `coordinator.meshServerHost`                 | string         | Hostname of the mesh-api server | `"0.0.0.0"` |
| `coordinator.meshServerPort`                 | int            | Port of the mesh-api server configuration | `2001` |
| `coordinator.pvcName`                        | string         | Name of a [Persistent Volume Claim](https://kubernetes.io/docs/concepts/storage/persistent-volumes/) to use for the Coordinator's state. Leave empty to create a new one using the configured StorageClass |
| `coordinator.replicas`                       | int            | Number of replicas for each control plane pod | `1` |
| `coordinator.repository`                     | string         | Name of the container registry to pull the coordinator image from | `"ghcr.io/edgelesssys/marblerun"` |
| `coordinator.sealDir`                        | string         | Path to the directory used for sealing data. Needs to be consistent with the persisten storage setup | `"/coordinator/data/"` |
| `coordinator.simulation`                     | bool           | SGX simulation settings, set to `true` if your not running on an SGX capable cluster | `false` |
| `coordinator.storageClass`                   | string         | Kubernetes [StorageClass](https://kubernetes.io/docs/concepts/storage/storage-classes/) to use for creating the Coordinator PVC. Leave empty to use the default StorageClass |
| `coordinator.version`                        | string         | Version of the coordinator container image to pull | `"v1.1.0"` |
| `global.coordinatorComponentLabel`           | string         | Control plane label. Do not edit | `"edgeless.systems/control-plane-component"` |
| `global.coordinatorNamespaceLabel`           | string         | Control plane label. Do not edit | `"edgeless.systems/control-plane-ns"` |
| `global.podAnnotations`                      | object         | Additional annotations to add to all pods | `{}`|
| `global.podLabels`                           | object         | Additional labels to add to all pods | `{}` |
| `marbleInjector.CABundle`                    | string         | MutatingWebhook CA bundle. Automatically configured by the MarbleRun CLI. Ignore when using standalone helm chart | `""` |
| `marbleInjector.image`                       | string         | Name of the marbleInjector container image | `"coordinator"` |
| `marbleInjector.start`                       | bool           | Start the marbleInjector webhook | `false` |
| `marbleInjector.replicas`                    | int            | Replicas of the marbleInjector webhook | `1` |
| `marbleInjector.repository`                  | string         | Name of the container registry to pull the marbleInjector image from | `"ghcr.io/edgelesssys/marblerun"` |
| `marbleInjector.version`                     | string         | Version of the marbleInjector container image to pull | `"v1.1.0"` |
| `marbleInjector.useCertManager`              | bool           | Set to use cert-manager for certificate provisioning. Required when using standalone helm chart for installation | `false` |
| `marbleInjector.objectSelector`              | object         | ObjectSelector to trigger marble-injector mutation, See the [K8S documentation](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-objectselector) for more information | `{matchExpressions:[{key:"marblerun/marbletype",operator:"Exists"}]}` |
| `marbleInjector.namespaceSelector`           | object         | NamespaceSelector to trigger marble-injector mutation, See the [K8S documentation](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/#matching-requests-namespaceselector) for more information | `{}` |
| `nodeSelector`                               | object         | NodeSelector section, See the [K8S documentation](https://kubernetes.io/docs/concepts/configuration/assign-pod-node/#nodeselector) for more information | `{"beta.kubernetes.io/os": "linux"}` |
| `tolerations`                                | object         | Tolerations section, See the [K8S documentation](https://kubernetes.io/docs/concepts/scheduling-eviction/taint-and-toleration/) for more information | `{key:"sgx.intel.com/epc",operator:"Exists",effect:"NoSchedule"}` |
| `dcap.qpl`                                   | string         | SGX quote provider library (QPL) to use. Needs to be "intel" if the libsgx-dcap-default-qpl is to be used, otherwise az-dcap-client is used by default | `"azure"` |
| `dcap.pccsUrl`                               | string         | URL of the PCCS. Only applicable if `dcap.qpl=intel` | `"https://localhost:8081/sgx/certification/v3/"`
| `dcap.useSecureCert`                         | string         | Whether or not the TLS certificate of the PCCS should be verified | `"TRUE"`

## Add new version (maintainers)

```bash
cd <marblerun-repo>
helm package charts
mv marblerun-x.x.x.tgz <helm-repo>/stable
cd <helm-repo>
helm repo index stable --url https://helm.edgeless.systems/stable
```
