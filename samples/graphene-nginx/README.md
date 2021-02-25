# Graphene nginx sample
This sample is a slightly modified [Graphene nginx sample](https://github.com/oscarlab/graphene/tree/master/Examples/nginx) to run in Marblerun.

You can build the sample as follows:
```sh
export GRAPHENEDIR=[PATH To Your Graphene Folder]
make
```

To marbleize the sample we edited `nginx.manifest.template`. Common things to change or add are:
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

The provided template files shipped with this sample has all changes made.
However, you might want to compare these changes with the [original template](https://github.com/oscarlab/graphene/tree/master/Examples/nginx/nginx.manifest.template) 
or have a look at the [patch](patch)

We also replaced `sgx.trusted_files.cert` and `sgx.trusted_files.privkey` with
```toml
sgx.protected_files.cert    = "file:install/conf/server.crt"
sgx.protected_files.privkey = "file:install/conf/server.key"
```
We delete these files before running nginx as they are handled by Marblerun.
The server certificate, for instance, will be injected by Marblerun. See
[manifest.json](manifest.json) on how this is specified.

As we increased the `enclave_size`, we might need to decrease the number of `worker_processes` in `nginx-graphene.conf.template` to 1 or 2.
Again we mention this for your information. The changes are already made to the conf.

We now build the sample as follows:
```sh
wget https://github.com/edgelesssys/marblerun/releases/latest/download/premain-graphene
make SGX=1
rm install/conf/server.*  # handled by Marblerun
```


Once the [Coordinator instance is started](../../BUILD.md#run-the-coordinator) with `EDG_COORDINATOR_MESH_ADDR=localhost:2001` and [initialized with the Manifest](../../BUILD.md#create-a-manifest), you can run your application:
```sh
EDG_MARBLE_COORDINATOR_ADDR=localhost:2001 EDG_MARBLE_TYPE=frontend EDG_MARBLE_UUID_FILE=uuid EDG_MARBLE_DNS_NAMES=localhost SGX=1 ./pal_loader nginx
```
