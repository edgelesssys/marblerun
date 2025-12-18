# Azure managed HSM integration

MarbleRun integrates with [Azure Managed HSM](https://learn.microsoft.com/en-us/azure/key-vault/managed-hsm/overview).
This feature allows users to use an HSM key to encrypt the [sealed data encryption key](../architecture/security.md#encryption-of-state) of the MarbleRun Coordinator,
using the [Secure Key Release (SKR)](https://learn.microsoft.com/en-us/azure/confidential-computing/concept-skr-attestation) feature of Azure Managed HSM.
SKR allows users to define a policy that restricts an HSM key to be used only by applications that meet the policy’s attestation requirements.

To enable the feature for your MarbleRun deployment, enable the [`AzureHSMSealing` feature gate in your manifest](../workflows/define-manifest.md#config).

Follow [the set up instructions](../workflows/hsm-sealing.md) to learn how to provision an Azure Managed HSM and configure it for use with MarbleRun.
