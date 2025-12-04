# Azure managed HSM integration

MarbleRun has an integration for [Azure Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview).
This feature allows users to use an HSM key to encrypt data managed by MarbleRun,
using the [Secure Key Release (SKR)](https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation) feature of Azure Managed HSM.
SKR allows users to define a policy for a key in the HSM that enables the key to be used only by applications that meet the attestation requirements defined in the policy.

To enable the feature for your MarbleRun deployment, enable the [`AzureHSMSealing` feature gate in your manifest](../workflows/define-manifest.md#config).

## Setting up Azure Managed HSM for MarbleRun

The following gives a brief overview of how to set up an HSM for use with MarbleRun.
View the [official documentation](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/quick-create-cli) for more details on how to provision and manage HSMs.

1. Start by setting up a resource group for your HSM:

    ```bash
    az group create --name "marblerun-hsm" --location "uksouth"
    ```

    The location should ideally match the location of your MarbleRun deployment.

2. Create the HSM:

    ```bash
    user_oid=$(az ad signed-in-user show --query id -o tsv)
    az keyvault create --hsm-name "MarbleRunHSM" --resource-group "marblerun-hsm" --location "uksouth" --administrators $user_oid --retention-days 7
    ```

3. Activate the HSM

    ```bash
    mkdir hsm
    openssl req -newkey rsa:2048 -nodes -keyout hsm/cert_0.key -x509 -days 365 -out hsm/cert_0.cer
    openssl req -newkey rsa:2048 -nodes -keyout hsm/cert_1.key -x509 -days 365 -out hsm/cert_1.cer
    openssl req -newkey rsa:2048 -nodes -keyout hsm/cert_2.key -x509 -days 365 -out hsm/cert_2.cer

    az keyvault security-domain download --hsm-name MarbleRunHSM --sd-wrapping-keys ./hsm/cert_0.cer ./hsm/cert_1.cer ./hsm/cert_2.cer --sd-quorum 2 --security-domain-file hsm/MarbleRunHSM-SD.json
    ```

    Store the certificates and security domain file securely. They're needed for disaster recovery of your HSM.

4. Assign yourself permissions to create keys in the HSM:

    ```bash
    az keyvault role assignment create --assignee $user_oid --role "Managed HSM Crypto User" --hsm-name MarbleRunHSM --scope /
    ```

5. Create a key release policy for your key

    The key release policy controls what enclaves are allowed to access the key it's bound to.
    For more details on how to configure your policies, see [Azure's policy examples](https://learn.microsoft.com/en-us/azure/confidential-computing/skr-policy-examples).

    Make sure that `authority` matches the location you are deploying MarbleRun to.

    The following policy allows a v1.8.0 MarbleRun Coordinator deployed in the UK South region to access the key.
    Save it a file named `policy.json`.

    ```json
    {
        "version": "1.0.0",
        "anyOf": [
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

6. Create a key for MarbleRun in the HSM

    ```bash
    az keyvault key create --exportable true --hsm-name "MarbleRunHSM" --kty OCT-HSM --name "marblerun-skr-key" --policy ./policy.json
    ```

7. Create a Service Principal for the MarbleRun Coordinator to access the HSM

    ```bash
    az ad sp create-for-rbac --name "marblerun-coordinator-hsm-sp" > hsm/coordinator-sp-credentials.json
    ```

8. Assign the "Managed HSM Crypto Service Release User" role to the Service Principal

    This role allows the Service Principal to request key release of the key we created earlier.
    To actually receive the key, the request must be made from an enclave that meets the requirements from the attestation policy.

    ```bash
    hsm_id=$(az keyvault show --hsm-name MarbleRunHSM --query id -o tsv)
    app_id=$(az ad sp list --display-name "marblerun-coordinator-hsm-sp" --query "[].id" -o tsv)
    az keyvault role assignment create --assignee-object-id $app_id --assignee-principal-type ServicePrincipal --role "Managed HSM Crypto Service Release User" --hsm-name MarbleRunHSM --scope /keys/marblerun-skr-key
    ```

## Configuring MarbleRun to use Azure Managed HSM

With the HSM set up, MarbleRun is now ready to request the key for sealing.
For this, the Coordinator needs credentials for the Service Principal and information about how to retrieve the key.

Retrieve the credentials from the Service Principal JSON file:

```bash
client_id=$(jq -r '.appId' hsm/coordinator-sp-credentials.json)
client_secret=$(jq -r '.password' hsm/coordinator-sp-credentials.json)
tenant_id=$(jq -r '.tenant' hsm/coordinator-sp-credentials.json)

vault_url=$(az keyvault show --hsm-name MarbleRunHSM --query 'properties.hsmUri' -o tsv)
```

<Tabs groupId="installation">

<TabItem value="helm" label="Helm">

Add the following to your Helm's `values.yaml` file:

```yaml
coordinator:
    azureCredentials:
        clientID: ${client_id}
        tenantID: ${tenant_id}
        clientSecret: ${client_secret}
        # Optionally, set "secretName" to the name of a pre-configured secret
        # containing AZURE_CLIENT_ID, AZURE_TENANT_ID, and AZURE_CLIENT_SECRET
        # secretName: ""
    hsm:
        keyName: "marblerun-skr-key"
        vaultURL: ${vault_url}
        # Make sure this matches the location of your deployment, and the value you set in the key policy
        maaURL: "https://shareduks.uks.attest.azure.net"
        # Optionally, set to use a specific key version
        keyVersion: ""
```

</TabItem>

<TabItem value="standalone" label="Standalone">

Set the following environment variables to provided the needed information:

```bash
# Azure credentials
export EDG_AZURE_CLIENT_ID=${client_id}
export EDG_AZURE_CLIENT_SECRET=${client_secret}
export EDG_AZURE_TENANT_ID=${tenant_id}

# HSM key information
export EDG_AZURE_HSM_KEY_NAME="marblerun-skr-key"
export EDG_AZURE_HSM_KEY_VERSION="" # Optionally, set to use a specific key version
export EDG_AZURE_HSM_VAULT_URL=${vault_url}

# MAA URL. Make sure this matches the location of your deployment, and the value you set in the key policy
export EDG_MAA_URL="https://shareduks.uks.attest.azure.net"
```

</TabItem>
</Tabs>
