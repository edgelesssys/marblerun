# Occlum "Hello World!" sample
This sample shows how to run an [Occlum](https://github.com/occlum/occlum) application in Marblerun. In essence, you have to add the `premain-occlum` process to your Occlum image and use it as an entry point for your instance. `premain` will contact the Coordinator, set up the environment, and run the actual application. Look into the [Makefile](Makefile) for details.

## Requirements
First, get Occlum and its build toolchain up and running. This can become quite complex if you run it on your existing environment. Therefore, we use the official Docker image and expose the SGX device to it:

```sh
docker run -it --network host --device /dev/sgx occlum/occlum:0.22.0-ubuntu18.04
```

Note that we also chose `--network host` here, as we assume you do not run the coordinator in the same Docker instance. **This option is potentially insecure in production use**, as it disables the isolation of the container network. For a production setup, we recommend that you choose a setup that exposes the coordinator to the container.

## Build
Inside the Docker instance, clone the Marblerun repository and run the Makefile included in this directory. It will automatically build the premain process and "Hello World" application, create the Occlum instance and run `occlum build` to create the final image.

```sh
git clone https://github.com/edgelesssys/marblerun.git
cd marblerun/samples/occlum-hello
make
```

## Run
We assume that the Coordinator is run with the following environment variables:

- EDG_COORDINATOR_MESH_ADDR=localhost:2001
- EDG_COORDINATOR_CLIENT_ADDR=localhost:4433
- EDG_COORDINATOR_DNS_NAMES=localhost
- EDG_COORDINATOR_SEAL_DIR=$PWD

Once the [Coordinator instance is running](../../BUILD.md#run-the-coordinator), upload the manifest to the Coordinator:

```
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

Now we automatically run our application with the help of the Makefile:
```sh
make run
```

Or manually:
```sh
cd occlum_instance
occlum run /bin/premain-occlum /bin/hello
```

## Troubleshooting
* If you receive the following error message on launch:

    ```
    fatal error: failed to reserve page summary memory
    ```

    Make sure you allocated enough memory in `enclave.json`. The most important parameters are `user_space_size` and `default_mmap_size`. For safe values to start, check out the provided [demo manifest](Occlum.json).

* Else, if you receive:

    ```
    ERROR: Failed to spawn the target process.
    Did you use the correct path for your target application (for example: occlum run /bin/premain-occlum /bin/hello_world)?
    Have you allocated enough memory?
    panic: errno -1
    ```

    Make sure you specified the correct filename of your target application, and also make sure enough memory is allocated. To find out the specific reason for why this error is occuring, you can set the environment variable `OCCLUM_LOG_LEVEL=error` by appending it in front of your run command like this:

    ```sh
    OCCLUM_LOG_LEVEL=error make run
    ```

    or:
    ```sh
    OCCLUM_LOG_LEVEL=error occlum run /bin/premain-occlum /bin/hello
    ```

    Search for `SpawnMusl`. This entry will contain the error encountered when spawning your application from Marblerun's premain process.
