# Demo of graphene + marblerun

* Create an Azure Kubernetes-Cluster using `start_cluster.sh`

```bash
./start_cluster az subscriptionID> <az resource group> <az cluster name> <az cluster #nodes>
```

* Install Marblerun on the Clutser

```bash
marblerun install
```

* Get the Coordinator's address and set the DNS

```bash
kubectl -n marblerun port-forward svc/coordinator-client-api 25555:25555 --address localhost >/dev/null &
export MARBLERUN=localhost:25555
```

* Check coordinator status, this should return status 2: ready to accept manifest.

```bash
marblerun status $MARBLERUN
```

* Set the manifest

```bash
marblerun manifest set redis-manifest.json $MARBLERUN
```

* Create and annotate redis namespace

```bash
kubectl namespace create redis
marblerun namespace add redis
```

* Deploy redis using helm

```bash
helm install -f ./kubernetes/values.yaml redis ./kubernetes -n redis
```

* Forward redis-server port

```bash
kubectl -n redis port-forward svc/redis 6379:6379 --address localhost >/dev/null &
```

* Wait for redis-server to start, this might take a moment
    * Basically we wait for this output
    
    ```bash
    kubectl logs redis-0 -n redis
    ...
    7:M 29 Mar 2021 12:25:40.076 # Server initialized
    7:M 29 Mar 2021 12:25:40.108 * Ready to accept connections
    ```

* You can now connect to the redis server using `redis-cli`

```bash
redis-cli -h localhost -p 6379
```

## Building the Docker image

First, get Graphene up and running. You can use either the [Building](https://graphene.readthedocs.io/en/latest/building.html) or [Cloud Deployment](https://graphene.readthedocs.io/en/latest/cloud-deployment.html) guide to build and initially setup Graphene.

Assuming you have built Graphene in `/graphene` copy the redis-server.manifest.template into the `/graphene/Examples/redis`

```bash
cp ./redis-server.manifest.template /graphene/Examples/redis/redis-server.manifest.template
```

Next we can build the Docker image:

```bash
docker build --tag graphene/redis -f ./Dockerfile /graphene
```

The current Dockerfile is poorly optimized and can probably be configured to be smaller and more efficient, but for the sake of this demo it works
