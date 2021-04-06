# Demo of graphene + marblerun

First, ensure you have access to a Kubernetes cluster with SGX-enabled nodes and kubectl installed and configured.
Probably the easiest way to get started is to run Kubernetes on an [Azure Kubernetes Service (AKS)](https://docs.microsoft.com/en-us/azure/confidential-computing/confidential-nodes-aks-get-started), which offers SGX-enabled nodes.

* Install Marblerun on the Clutser

    ```bash
    marblerun install
    ```

* Wait for the Coordinator to be ready

    ```bash
    kubectl -n marblerun get pod -l edgeless.systems/control-plane-component=coordinator -o jsonpath="{.items[0].status.phase}"
    ```

* Port-forward the client API service to localhost

    ```bash
    kubectl -n marblerun port-forward svc/coordinator-client-api 25555:25555 --address localhost >/dev/null &
    export MARBLERUN=localhost:25555
    ```

* Check Coordinator's status, this should return status `2: ready to accept manifest`.

    ```bash
    marblerun status $MARBLERUN
    ```

* Set the manifest

    ```bash
    marblerun manifest set redis-manifest.json $MARBLERUN
    ```

* Create and add the redis namespace to Marblerun

    ```bash
    kubectl create namespace redis
    marblerun namespace add redis
    ```

* Deploy redis using helm

    ```bash
    helm install -f ./kubernetes/values.yaml redis ./kubernetes -n redis
    ```

* Wait for the redis server to start, this might take a moment

    * Basically we wait for this output

        ```bash
        kubectl logs redis-master-0 -n redis
        ...
        7:M 29 Mar 2021 12:25:40.076 # Server initialized
        7:M 29 Mar 2021 12:25:40.108 * Ready to accept connections
        ```

* Port-forward the redis service to localhost

    ```bash
    kubectl -n redis port-forward svc/redis 6379:6379 --address localhost >/dev/null &
    ```

* You can now connect to the redis server using `redis-cli`

    * Make sure you have the latest redis-cli with TLS support:

        ```bash
        wget http://download.redis.io/redis-stable.tar.gz
        tar xzf redis-stable.tar.gz
        make BUILD_TLS=yes -C redis-stable &&  cp redis-stable/src/redis-cli /usr/local/bin
        ```

    * Obtain the Coordinator's CA certificate

        ```bash
        marblerun certificate root $MARBLERUN -o marblerun.crt
        ```

    * Connect with the redis-cli

        ```bash
        redis-cli -h localhost -p 6379 --tls --cacert marblerun.crt
        localhost:6379> set mykey somevalue
        OK
        localhost:6379> get mykey
        "somevalue"
        ```

## Building the Docker image

First, get Graphene up and running. You can use either the [Building](https://graphene.readthedocs.io/en/latest/building.html) or [Cloud Deployment](https://graphene.readthedocs.io/en/latest/cloud-deployment.html) guide to build and initially setup Graphene.

Assuming you have built Graphene in `/graphene` copy the redis-server.manifest.template into the `/graphene/Examples/redis`

```bash
cp ./redis-server.manifest.template /graphene/Examples/redis/redis-server.manifest.template
```

Next we can build the Docker image:

```bash
docker build --tag ghcr.io/edgelesssys/redis-graphene-marble -f ./Dockerfile /graphene
```

The current Dockerfile is poorly optimized and can probably be configured to be smaller and more efficient, but for the sake of this demo it works
