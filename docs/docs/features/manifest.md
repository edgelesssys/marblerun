# Manifest and deployment updates

The manifest is a JSON document that defines the essential properties of your deployment: allowed software packages, secrets, access control, update policy, etc.
Particularly, the manifest contains all information required by the [Coordinator](../getting-started/coordinator.md) to verify the confidentiality and integrity of a newly spawned [Marble](../getting-started/marbles.md).
On successful verification, the Coordinator provisions the Marble with configuration and secrets.

As a cluster owner, you can define in the manifest how rigid you want your deployment to be.

## Immutable deployment

In an immutable deployment, you initialize MarbleRun with a permanent manifest that won't allow any changes later on.
Clients of such a deployment don't need to trust any other party because they can audit the manifest and verify its enforcement via [remote attestation](attestation.md).
Choose this approach for deployments with a limited lifetime.

## Deployment with updatable packages

The manifest allows to [permit a user to update existing packages of a deployment](../workflows/define-manifest.md#roles).
Clients of such a deployment need to trust the vendors of these packages to provide legitimate software updates.
Choose this approach for deployments with a well-defined scope, but a possibly longer lifetime.

## Fully updatable deployment

<enterpriseBanner/>

The manifest allows to [permit a user to update the full manifest](../workflows/define-manifest.md#roles).
With such a deployment, this user usually needs to be a trusted party.
Choose this approach for deployments that require full flexibility.

### Multi-party update

Depending on the use case, it may not be acceptable that a single user can update the full manifest.
MarbleRun supports [defining a group of users](../workflows/define-manifest.md#roles) that must acknowledge the newly uploaded manifest before it's applied.
