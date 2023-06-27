# Adding a service

Adding a service to your application requires three steps, which are described in the following.

## **Step 1:** Get your service ready for MarbleRun

To get your service ready for MarbleRun, you need to rebuild it with one of the supported [runtimes](../features/runtimes.md):
* [EGo](../building-services/ego.md)
* [Edgeless RT](https://github.com/edgelesssys/marblerun/blob/master/samples/helloc%2B%2B)
* [Gramine](../building-services/gramine.md)
* [Occlum](../building-services/occlum.md)

### Make your service use the provided TLS credentials

Skip this step, when using EGo with [TTLS](../features/transparent-TLS.md).

Quick refresher: MarbleRun's Coordinator issues TLS credentials for each verified Marble (i.e., a service running in a secure enclave) as is described in our [secrets management chapter](../features/secrets-management.md).

The TLS X.509 certificate and the corresponding private key can be securely passed to a service through files, environment variables, or command line arguments. This is defined in the manifest as is described in our [writing a manifest hands-on](../workflows/define-manifest.md#marbles).

Make sure that your service reads the credentials from one of these sources, e.g., the file `/tmp/mycert.cert` or the environment variable `MY_PRIVATE_KEY`, and uses them for internal and external connections. If you're lucky, your service already does this and you don't need to change a thing in the code.

## **Step 2:** Define your service in the manifest

Now that your service is ready, you need to make two types of entries in the manifest regarding its properties and parameters.

### **Step 2.1:** Define the enclave software package

As is described in more detail in our [writing a manifest hands-on](../workflows/define-manifest.md#packages), the manifest contains a section `Packages`, in which allowed enclave software packages are defined.

#### EGo / EdgelessRT
To add an entry for your EGo / EdgelessRT service, run the `oesign` tool on the enclave file you built in the previous step as follows. (`oesign` is installed with [Edgeless RT](https://github.com/edgelesssys/edgelessrt).)

```bash
oesign eradump -e enclave.signed
```

The tool's output is similar to the following.

```json
{
    "UniqueID": "6b2822ac2585040d4b9397675d54977a71ef292ab5b3c0a6acceca26074ae585",
    "SignerID": "5826218dbe96de0d7b3b1ccf70ece51457e71e886a3d4c1f18b27576d22cdc74",
    "SecurityVersion": 1,
    "ProductID": 3
}
```

#### Gramine

To add an entry for your Gramine service, run the `gramine-sgx-get-token` tool on the `.sig` file you built in the previous step as follows. (`gramine-sgx-get-token` is installed with [Gramine](https://github.com/gramineproject/gramine/).)


```bash
gramine-sgx-get-token --sig hello.sig
```

The tool's output is similar to the following.

```json
Attributes:
    mr_enclave:  72612ea17be998f098459ff3cdc0daa0d592cec85115db8e152b10fc6df033a7
    mr_signer:   ed81204cd726dcff2dc4c498bdfcef63a2b02009ef188e7e2914c37a7e99b547
    isv_prod_id: 1
    isv_svn:     3
    attr.flags:  0600000000000000
    attr.xfrm:   1f00000000000000
    misc_select: 00000000
    misc_mask:   00000000
    modulus:     09d6497ec75a05a2280974b7e5b39422...
    exponent:    3
    signature:   4b6db90216e6a5e8447812f7f0107317...
    date:        2021-08-18
```

#### Occlum

To add an entry for your Occlum service, run the MarbleRun CLI on the Occlum instance you built in the previous step as follows.

```bash
marblerun sgxsdk-package-info ./occlum-instance
```

The output is similar to the following.

```json
PackageProperties for Occlum image at './occlum-instance':
UniqueID (MRENCLAVE)      : ccad2391e0b79d9108209135c26b2c276c5a24f4f55bc67ccf5ab90fd3f5fc22
SignerID (MRSIGNER)       : 83d719e77deaca1470f6baf62a4d774303c899db69020f9c70ee1dfc08c7ce9e
ProductID (ISVPRODID)     : 1
SecurityVersion (ISVSVN)  : 3
```


Use `UniqueID` (i.e., `MRENCLAVE` in Intel SGX speak) or the triplet of `SignerID` (i.e., `MRSIGNER`), `SecurityVersion`, and `ProductID` to add an entry in the `Packages` section.

### **Step 2.2:** Define the parameters

Now you can define with which parameters (i.e., files, environment variables, and command line arguments) your service is allowed to run. This is done in the `Marbles` section of the manifest as is described in our [writing a manifest hands-on](../workflows/define-manifest.md#marbles). When using EGo, define all TTLS connections as described in the [manifest hands-on](../workflows/define-manifest.md#tls).

Otherwise, as discussed in [Step #1](#make-your-service-use-the-provided-tls-credentials), make sure that the TLS credentials for your service (i.e., `MarbleRun.MarbleCert.Cert` and `MarbleRun.MarbleCert.Private`) are injected such that your service finds them at runtime.

## **Step 3:** Start your service

When you start your service, you need to pass in a couple of configuration parameters through environment variables. Here is an example:

```bash
EDG_MARBLE_COORDINATOR_ADDR=coordinator-mesh-api.marblerun:2001 \
EDG_MARBLE_TYPE=mymarble \
EDG_MARBLE_UUID_FILE=$PWD/uuid \
EDG_MARBLE_DNS_NAMES=localhost,myservice \
erthost enclave.signed
```

`erthost` is the generic host for EdgelessRT Marbles, which will load your `enclave.signed`.
For EGo (`ego marblerun`), Gramine (`gramine-sgx`), and Occlum (`occlum run`) use their particular launch mechanism instead.

The environment variables have the following purposes.

* `EDG_MARBLE_COORDINATOR_ADDR` is the network address of the Coordinator's API for Marbles. When you deploy the Coordinator using our Helm repository as is described in our [deploying MarbleRun hands-on](../deployment/kubernetes.md), the default address is `coordinator-mesh-api.marblerun:2001`.

* `EDG_MARBLE_TYPE` needs to reference one entry from your manifest's `Marbles` section.

* `EDG_MARBLE_UUID_FILE` is the local file path where the Marble stores its UUID. Every instance of a Marble has its unique and public UUID. The file is needed to allow a Marble to restart under its UUID.

* `EDG_MARBLE_DNS_NAMES` is the list of DNS names the Coordinator will issue the Marble's certificate for.

## **Step 4:** Deploy your service with Kubernetes

Typically, you'll write a Kubernetes resource definition for your service, which you'll deploy with the Kubernetes CLI, Helm, or similar tools.

For your services to take advantage of MarbleRun, they need to be "added to the mesh" by having the data plane configuration injected into their pods.
This is typically done by labeling the deployment, or pod with the `marblerun/marbletype` Kubernetes label.
This label triggers automatic configuration injection when the resources are created. (See [auto injection](../features/kubernetes-integration.md) for more on how this works.)

An example for a Marble of type `web` could look like this:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
  namespace: emojivoto
  labels:
    app.kubernetes.io/name: web
    app.kubernetes.io/part-of: emojivoto
    app.kubernetes.io/version: v1
    marblerun/marbletype: web
```

This will result in the following configuration being injected when your resources are created:

```yaml
spec:
  containers:
    - env:
      - name: EDG_MARBLE_COORDINATOR_ADDR
        value: coordinator-mesh-api.marblerun:2001
      - name: EDG_MARBLE_TYPE
        value: web
      - name: EDG_MARBLE_DNS_NAMES
        value: "web,web.emojivoto,web.emojivoto.svc.cluster.local"
      - name: EDG_MARBLE_UUID_FILE
        value: "$PWD/uuid"
```

Refer to our [emojivoto](https://github.com/edgelesssys/emojivoto) app for complete Helm chart examples.
