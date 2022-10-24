# Building a service: Occlum
Running an Occlum app with MarbleRun requires some changes to its manifest.

## Requirements
Set up an environment to create Occlum images. For an easy start, we recommend that you use either the official [Occlum Docker image](https://hub.docker.com/r/occlum/occlum) or use [our provided Dockerfile](https://github.com/edgelesssys/marblerun/blob/master/samples/occlum-hello/Dockerfile). For a working DCAP remote attestation environment, we recommend [our cloud deployment guide](deployment/cloud.md).

To build your service, you can start with [Occlum's Introduction](https://github.com/occlum/occlum#introduction) to get your application up and running, and then come back here to adapt it for use with MarbleRun.

## Configuration
### Premain executable
Add our pre-built [premain-libos](https://github.com/edgelesssys/marblerun/releases/download/latest/premain-libos) executable to your Occlum image, e.g., by copying it to `image/bin/premain-libos`. By default, Occlum restricts executable files to the `/bin` directory. If you placed the `premain-libos` binary to a different path, you need to adjust this setting accordingly.

Finally, define the original entry point for your Occlum instance as the first `Argv` parameter for your Marble in MarbleRun's `manifest.json`. See [Defining a manifest](workflows/define-manifest.md) for more information on how to define the `Argv` parameters. This lets MarbleRun launch your application after it succeeded in authenticating with the Coordinator and provides entrypoint pinning similar to the one offered in `Occlum.json`.

### Environment variables
The Marble needs to retrieve the MarbleRun specific configuration parameters via environment variables, as [described under Step 3 in "Adding a service"](workflows/add-service.md).

To pass environment variables to the enclave, Occlum requires them to be specified in the `env` section in `Occlum.json`.

You can provide default (hardcoded) values under `default`, and you may also define them additionally as `untrusted` in case you want to allow changes to the Marble configuration after build time.

For example, this configuration:
```javascript
"env": {
    "default": [
        "OCCLUM=yes",
        "EDG_MARBLE_COORDINATOR_ADDR=localhost:2001",
        "EDG_MARBLE_TYPE=hello",
        "EDG_MARBLE_UUID_FILE=uuid",
        "EDG_MARBLE_DNS_NAMES=localhost"
    ],
    "untrusted": [
        "EDG_MARBLE_COORDINATOR_ADDR",
        "EDG_MARBLE_TYPE",
        "EDG_MARBLE_UUID_FILE",
        "EDG_MARBLE_DNS_NAMES"
    ]
},
```

will allow you both to embed the expected default values during build time, but also let the user/host system change them during run time when a non-default Coordinator configuration is used.

### Resource limits
The premain process is written in Go. The enclave needs to have enough resources for the Go runtime, plus additional memory to launch your application.

We recommend starting with the following values which should work fine for light-weight to medium memory demanding applications:
```javascript
"user_space_size": "2048MB",
"default_mmap_size": "900MB"
"max_num_of_threads": 64
```

In case you are running into issues with memory demands, check out the [Resource Configuration Guide](https://github.com/occlum/occlum/blob/master/docs/resource_config_guide.md) provided by the Occlum team to debug and resolve issues related to resource limits.

## Troubleshooting

### fatal error: failed to reserve page summary memory

If you receive this error during the launch of your Occlum image, make sure you allocated enough memory in `Occlum.json` [as described above](#resource-limits). The most important parameters are `user_space_size` and `default_mmap_size`.

### Error returned from the p_sgx_get_quote_config API

If Occlum crashes during the quote generation with the following error message:
```
[get_platform_quote_cert_data ../qe_logic.cpp:346] Error returned from the p_sgx_get_quote_config API. 0xe019
thread '<unnamed>' panicked at 'assertion failed: `(left == right)`
left: `SGX_QL_SUCCESS`,
right: `SGX_QL_NETWORK_ERROR`: fail to launch QE', src/util/sgx/dcap/quote_generator.rs:22:13
```

You might need to check the DCAP configuration on your system. Note that when using the Docker image, the local Intel DCAP configuration needs to be correctly set from **inside the container.**

If you use an Azure Confidential Computing machine, you can use our [provided Dockerfile](https://github.com/edgelesssys/marblerun/blob/master/samples/occlum-hello/Dockerfile) which patches the official Occlum image to use the Azure DCAP client, which handles the configuration automatically.

For other DCAP setups, please consult the documentation of your Intel Provisioning Certificate Caching Service (PCCS) service running locally or remotely.

### Other issues
If you are running into other issues, Occlum's error logging might help:
```bash
OCCLUM_LOG_LEVEL=error occlum run /bin/premain-libos
```
