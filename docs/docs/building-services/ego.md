# Building a service: EGo
To get your Go service ready for MarbleRun, we provide two solutions. With [Transparent TLS (TTLS)](features/transparent-TLS.md) you are able to use your existing applications without any code changes. Alternatively, you can adapt and recompile your application to manually handle the TLS credentials. Details are given in the following.

## TTLS
Simply follow the steps on [adding a service](workflows/add-service.md). No code changes and no recompiling needed.

## Manual TLS credentials handling

If your service already uses TLS and gets the credentials from, e.g., a file, you just need to [adapt the manifest](workflows/add-service.md#make-your-service-use-the-provided-tls-credentials). Otherwise, you need to make small code changes.

We provide a convenience package called [github.com/edgelesssys/ego/marble](https://pkg.go.dev/github.com/edgelesssys/ego/marble#GetTLSConfig). With it, a service can automatically get and use its MarbleRun TLS credentials. The following gives an example.
```Go
    serverCfg, err := marble.GetTLSConfig(false)
    if err != nil {
        log.Fatalf("Failed to retrieve server TLS config")
    }
    // use serverCfg, e.g., to create an HTTPS server
```

Finally, you need to re-build your service for the enclave environment with `ego-go` and sign it with `ego sign`. Please follow the build instructions for Go provided in our [Go sample](https://github.com/edgelesssys/marblerun/blob/master/samples/helloworld).
