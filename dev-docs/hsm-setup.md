# HSM set-up guide

1. Create a resource group for the HSM

    ```bash
    az group create --name "marblerun-hsm" --location uksouth
    ```

2. Create a Managed HSM pool

    ```bash
    oid=$(az ad signed-in-user show --query id -o tsv)
    az keyvault create --hsm-name "MarbleRunHSM" --resource-group "marblerun-hsm" --location "uksouth" --administrators $oid --retention-days 7
    ```

3. Activate the HSM

    ```bash
    mkdir hsm && cd hsm
    openssl req -newkey rsa:2048 -nodes -keyout cert_0.key -x509 -days 365 -out cert_0.cer
    openssl req -newkey rsa:2048 -nodes -keyout cert_1.key -x509 -days 365 -out cert_1.cer
    openssl req -newkey rsa:2048 -nodes -keyout cert_2.key -x509 -days 365 -out cert_2.cer

    az keyvault security-domain download --hsm-name MarbleRunHSM --sd-wrapping-keys ./cert_0.cer ./cert_1.cer ./cert_2.cer --sd-quorum 2 --security-domain-file MarbleRunHSM.json
    ```

4. Assign the "Managed HSM Crypto Officer" role to your user so you can create keys

    ```bash
    az keyvault role assignment create --assignee $oid --role "Managed HSM Crypto Officer" --hsm-name MarbleRunHSM --scope /
    az keyvault role assignment create --assignee $oid --role "Managed HSM Crypto User" --hsm-name MarbleRunHSM --scope /
    ```

5. Create a key release policy for your key

    The following policy will allow release of the key if the SignerID (MR_SIGNER) of the Coordinator enclave matches the expected value.
    Save the following to a file named `policy.json`.
    Make sure that
    * `authority` matches the MAA instance you are using, i.e. the `EDG_MAA_URL` value set for the Coordinator
    * the operators for each claim match the values of your Coordinator enclave. The config given here matches the Coordinator enclave of v1.8.0

    ```json
    {
        "version": "1.0.0",
        "allOf": [
            {
                "authority": "https://shareduks.uks.attest.azure.net",
                "allOf": [
                    {
                        "claim": "x-ms-sgx-mrsigner",
                        "equals": "43361affedeb75affee9baec7e054a5e14883213e5a121b67d74a0e12e9d2b7a"
                    },
                    {
                        "claim": "x-ms-sgx-svn",
                        "greaterOrEquals": 2
                    },
                    {
                        "claim": "x-ms-sgx-product-id",
                        "greaterOrEquals": 3
                    },
                    {
                        "claim": "x-ms-sgx-is-debuggable",
                        "equals": false
                    }
                ]
            }
        ]
    }
    ```

    For more details see [Azure's policy examples](https://learn.microsoft.com/en-us/azure/confidential-computing/skr-policy-examples).

6. Create a key for the application

    ```bash
    az keyvault key create --exportable true --hsm-name "MarbleRunHSM" --kty OCT-HSM --name "marblerun-skr-key" --policy ./policy.json
    ```

7. Create a service principal for the Coordinator to access the HSM

    ```bash
    az ad sp create-for-rbac --name "marblerun-coordinator-hsm-sp"
    ```

8. Assign the "Managed HSM Crypto Service Release User" role to the service principal

    ```bash
    hsm_id=$(az keyvault show --hsm-name MarbleRunHSM --query id -o tsv)
    app_id=$(az ad sp list --display-name "marblerun-coordinator-hsm-sp" --query "[].id" -o tsv)
    az keyvault role assignment create --assignee-object-id $app_id --assignee-principal-type ServicePrincipal --role "Managed HSM Crypto Service Release User" --hsm-name MarbleRunHSM --scope /keys/marblerun-skr-key
    ```
