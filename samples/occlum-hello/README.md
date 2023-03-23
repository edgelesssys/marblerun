# Occlum "Hello World!" sample

This sample shows how to run an [Occlum](https://github.com/occlum/occlum) application in MarbleRun. In essence, you have to add the `premain-libos` process to your Occlum image, use it as an entry point for your instance and supply the original entry point as an `Argv` value in MarbleRun's [manifest.json](manifest.json). `premain` will contact the Coordinator, set up the environment, and run the actual application. Take a look into the [Makefile](Makefile) for details.

## Requirements

First, get Occlum and its build toolchain up and running. This can become quite complex if you run it on your existing environment. Therefore, we use the official Docker image and expose the SGX device to it:

```sh
docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx occlum/occlum:0.29.3-ubuntu20.04
```

If you are trying to run this sample on Azure, you might want to use the provided [Dockerfile](Dockerfile) instead. It is based on the official Occlum image, but replaces the default Intel DCAP client with the [Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client). This is required to get correct quotes on Azure's Confidential Computing virtual machines. You can build and use the image in the following way:

```sh
# Assuming `samples/occlum-hello` is the current working directory
DOCKER_BUILDKIT=1 docker build -t occlum-azure .
docker run -it --network host --device /dev/sgx_enclave --device /dev/sgx_provision -v /dev/sgx:/dev/sgx occlum-azure
```

Note that we also chose `--network host` here, as we assume you do not run the coordinator in the same Docker instance. **This option is potentially insecure in production use**, as it disables the isolation of the container network. For a production setup, we recommend that you choose a setup that exposes the coordinator to the container.

## Build

Inside the Docker instance, clone the MarbleRun repository and run the Makefile included in this directory. It will automatically build the premain process and "Hello World" application, create the Occlum instance and run `occlum build` to create the final image.

```sh
# remove Occlum Go from path
PATH=":$PATH:" && PATH="${PATH//:\/opt\/occlum\/toolchains\/golang\/bin:/:}" && PATH="${PATH#:}" && PATH="${PATH%:}"
git clone https://github.com/edgelesssys/marblerun.git
cd marblerun/samples/occlum-hello
make
```

After you build the Occlum image, you need to retrieve either the `UniqueID` or the `SignerID`/`ProductID`/`SecurityVersion` triple for MarbleRun's [`manifest.json`](manifest.json). You can get the values using the MarbleRun CLI tool:

```sh
wget https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
chmod +x marblerun
./marblerun package-info ./occlum-instance
```

The output is similar to the following:

```sh
Detected Occlum image.
PackageProperties for Occlum image at './occlum-instance':
UniqueID (MRENCLAVE)      : ccad2391e0b79d9108209135c26b2c276c5a24f4f55bc67ccf5ab90fd3f5fc22
SignerID (MRSIGNER)       : 43361affedeb75affee9baec7e054a5e14883213e5a121b67d74a0e12e9d2b7a
ProductID (ISVPRODID)     : 0
SecurityVersion (ISVSVN)  : 0
```

From this point, you can take the `UniqueID` (or `SignerID`/`ProductID`/`SecurityVersion` triple) and insert it into [`manifest.json`](manifest.json).

If you want to change the entry point of your application, you can also edit the first `Argv` value in the manifest. This needs to be a path to the virtual file system of your Occlum image.

## Run

We assume that the Coordinator is run with the following environment variables:

- EDG_COORDINATOR_MESH_ADDR=localhost:2001
- EDG_COORDINATOR_CLIENT_ADDR=localhost:4433
- EDG_COORDINATOR_DNS_NAMES=localhost
- EDG_COORDINATOR_SEAL_DIR=$PWD

Once the [Coordinator instance is running](../../BUILD.md#run-the-coordinator), upload the manifest to the Coordinator:

```sh
curl -k --data-binary @manifest.json https://localhost:4433/manifest
```

Now we automatically run our application with the help of the Makefile:

```sh
make run
```

Or manually:

```sh
cd occlum_instance
occlum run /bin/premain-libos
```

## Troubleshooting

- If you receive the following error message on launch:

    ```sh
    fatal error: failed to reserve page summary memory
    ```

    Make sure you allocated enough memory in `enclave.json`. The most important parameters are `user_space_size` and `default_mmap_size`. For safe values to start, check out the provided [demo manifest](Occlum.json).

- Else, if you receive:

    ```sh
    ERROR: The entrypoint does not seem to exist: '/bin/your_application'
    Please make sure that you define a valid entrypoint in your manifest (for example: /bin/hello_world).
    panic: "invalid entrypoint definition in argv[0]"
    ```

    Make sure you specified the correct filename of your target application.

- If you are running into other issues, Occlum's error logging might help:

    ```sh
    OCCLUM_LOG_LEVEL=error make run
    ```

    or:

    ```sh
    OCCLUM_LOG_LEVEL=error occlum run /bin/premain-libos
    ```
