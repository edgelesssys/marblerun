# Monitoring and logging


## /status endpoint of client API

For status information, the Coordinator provides the `/status` endpoint in the client API.
It returns the following information:

- **1 recovery mode**: Either upload a key to unseal the saved state, or set a new manifest. Waiting for user input on [`/recover`](features/recovery.md).
- **2 waiting for a manifest**: Coordinator is ready to accept a manifest. Waiting for user input on [`/manifest`](workflows/set-manifest.md)
- **3 accepting marbles**: Coordinator is running correctly and ready to accept Marbles through the [Marble API](workflows/add-service.md)

## Kubernetes logs

If you are running on a Kubernetes cluster, details about the Coordinator can be retrieved through its log as follows.

```bash
kubectl -n marblerun logs -f marblerun-coordinator-xxxxxxxxxx-xxxxx
```

## Prometheus

To enable the Coordinators [Prometheus](https://prometheus.io/) instrumentation, set an environment variable with the address the Prometheus exporter should run at:

```bash
EDG_COORDINATOR_PROMETHEUS_ADDR=0.0.0.0:9944
```

The exporter then serves the `/metrics` endpoint under that address.

Here are the most important metrics for your monitoring setup:

- The state of the Coordinator. See the listing above for interpretation of status codes.
    ```bash
    coordinator_state 1
    ```

- Build and version information of the Coordinator.
    ```bash
    coordinator_version_info{commit="bd505dca04f78da57e2330263f9076839d906267",version="0.4.0"} 0
    ```

- Marbel activations are labeled with the Marbles type and UUID.
    ```bash
    marble_activations_total{type="frontend",uuid="4aac36cc-bbea-4db3-89ff-078ccad738f6"} 1
    marble_activations_success_total{type="frontend",uuid="4aac36cc-bbea-4db3-89ff-078ccad738f6"} 1
    ```

- gRPC metrics of the Marble API with prefix `grpc_server`

- HTTP metrics of the client API wiht prefix `server_client_api_http`


Going forward, plans are having a web dashboard with status and health information quickly accessible.
