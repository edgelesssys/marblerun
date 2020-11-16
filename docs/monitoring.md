# Monitoring and logging

As of now the monitoring for Marblerun is pretty rudimentary, but we are planning to improve this we future versions.
For basic status information, we provide the `/status` endpoint in the client API.
It will return information about the coordinator's current state:

- 0 recovery mode: Found a sealed state of an old seal key. Waiting for user input on [`/recover`](recovery.md).
- 1 uninitialized: Fresh start, initializing the coordinator.
- 2 waiting for a manifest: Waiting for user input on [`/manifest`](set-manifest.md)
- 3 accepting marbles: Accepting marbles through the [Marble API](add-service.md)

More details about the coordinator can be retrieved through its log:

```bash
kubectl -n marblerun logs -f marblerun-coordinator-5b9b4849c8-jbjwr
```

In the future, we are planning to support your favorite monitoring tool via logging through [Prometheus](https://prometheus.io/) and having a web dashboard with all status and health information quickly accessible.
