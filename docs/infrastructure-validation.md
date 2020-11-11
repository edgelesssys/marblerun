# Infrastructure Validation

Marblerun allows you to define several VM types you want to whitelist for your application to run on. This way you can make sure that when you deploy your application to a cluster with VM of type A, nobody can substitute one of the nodes with a VM of type B.

The incentive is that an update of the Trusted Computing components as the CPU, Provisioning Certificate Enclave, or Quoting Enclave might contain security relevant changes.
In the deployment of your application you want to make sure that it only runs on the latest up to date versions.
You can do so by specifying the particular version numbers in *Infrastructures* section of your manifest:

* **QESVN**: The Quoting Enclaves version number
* **PCESVN**: The Provisioning Certificate Enclave version number
* **CPUSVN**: The CPU version number
* **RootCA**: The Root Certificate of the remote attestation chain

```json
    "Infrastructures": {
        "Azure": {
            "QESVN": 2,
            "PCESVN": 3,
            "CPUSVN": [0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15],
            "RootCA": [3,3,3]
        },
        "Alibaba": {
            "QESVN": 2,
            "PCESVN": 4,
            "CPUSVN": [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0],
            "RootCA": [4,4,4]
        }
    }
```
