# Graphene nginx sample
This sample shows how to modify the [Graphene nginx sample](https://github.com/oscarlab/graphene/tree/master/Examples/nginx) to run in Marblerun.

*Prerequisite*: Graphene is set up and the nginx sample works.

To marbleize the sample you must edit `nginx.manifest.template`. Please append or replace the following values:
```toml
libos.entrypoint = "file:premain-graphene"
sgx.trusted_files.premain = "file:premain-graphene"
loader.argv0_override = "$(INSTALL_DIR)/sbin/nginx"
loader.insecure__use_host_env = 1
sgx.allowed_files.uuid = "file:uuid"
sgx.remote_attestation = 1
sgx.enclave_size = "1024M"
sgx.thread_num = 16
```
See [hello.manifest.template](../graphene-hello/hello.manifest.template) from the other sample for explanations of these values.

As you increased the `enclave_size`, you may need to decrease the number of `worker_processes` in `nginx-graphene.conf.template` to 1 or 2.

Build the sample as follows:
```sh
wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-graphene
make SGX=1
```

After you have [started a Coordinator instance](../../BUILD.md#run-the-coordinator) with `EDG_COORDINATOR_MESH_ADDR=localhost:2001` and [initialized it with the Manifest](../../BUILD.md#create-a-manifest), you can run your application:
```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=frontend EDG_MARBLE_UUID_FILE=uuid EDG_MARBLE_DNS_NAMES=localhost SGX=1 ./pal_loader nginx
```

TODO Get TLS certificate from Coordinator and store it as a Graphene Protected File.
