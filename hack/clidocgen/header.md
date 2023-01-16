# Command Line Interface (CLI)

We provide a command-line interface (CLI) for MarbleRun.
This CLI allows you to install MarbleRun on your cluster and interacts with the control plane through the Client API for all administrative tasks in the service mesh.

## Installation

To install the MarbleRun CLI on your machine you can use our pre-built binaries.

<tabs groupId="user">
<tabItem value="current-user" label="For the current user">

```bash
wget -P ~/.local/bin https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
chmod +x ~/.local/bin/marblerun
```

</tabItem>
<tabItem value="global" label="Global install (requires root)">

```bash
sudo wget -O /usr/local/bin/marblerun https://github.com/edgelesssys/marblerun/releases/latest/download/marblerun
sudo chmod +x /usr/local/bin/marblerun
```

</tabItem>
<tabItem value="build" label="Build from source">

To build the MarbleRun CLI, [Edgeless RT](https://github.com/edgelesssys/edgelessrt) needs to be installed on your machine.

```bash
git clone https://github.com/edgelesssys/marblerun && cd ./marblerun
go build -buildvcs=false -o marblerun ./cli
```

</tabItem>
</tabs>

### Requirements

The CLI requires an SGX quote verification library to verify quotes issued by the Coordinator.
You have different options depending on the environment the Coordinator is deployed to:

<tabs groupId="environement">
<tabItem value="azure" label="Azure CVM">

If the Coordinator is running on an Azure VM, the CLI relies on the [Azure DCAP Client](https://github.com/microsoft/Azure-DCAP-Client) to verify quotes.
To install the dependency on Ubuntu 20.04 run:

```bash
sudo apt-key adv --fetch-keys https://packages.microsoft.com/keys/microsoft.asc
sudo add-apt-repository 'deb [arch=amd64] https://packages.microsoft.com/ubuntu/20.04/prod focal main'
sudo apt update
sudo apt install -y az-dcap-client
```

</tabItem>
<tabItem value="generic" label="Generic SGX system">

Intel provides the `libsgx-dcap-default-qpl` library to facilitate SGX quote verification.
To install the dependency on Ubuntu 20.04 run:

```bash
sudo apt-key adv --fetch-keys https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key
sudo add-apt-repository 'https://download.01.org/intel-sgx/sgx_repo/ubuntu main'
sudo apt update
sudo apt install -y libsgx-dcap-default-qpl
```

Follow [Intel's documentation](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/qpl/README.md#configuration) to configure access to the PCCS.
</tabItem>
</tabs>

## Reference

Usage:

```terminal
marblerun [command]
```
