# Edgeless Mesh

![logo](docs/assets/mesh_text.png)

[![GitHub Actions Status][github-actions-badge]][github-actions]
[![GitHub license][license-badge]](LICENSE)
[![Go Report Card][go-report-card-badge]][go-report-card]

[Edgeless Mesh](https://www.edgeless.systems/) is a framework for creating distributed confidential-computing apps.

Build your confidential microservices with [Edgeless RT][edgelessrt], distribute them with Kubernetes on an SGX-enabled cluster, and let Edgeless Mesh take care of the rest. Deploy end-to-end secure and verifiable AI pipelines or crunch on sensitive big data in the cloud. Confidential computing at scale has never been easier.

Edgeless Mesh guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON. Edgeless Mesh verifies the integrity of services, bootstraps them, and sets up encrypted connections between them.

If a node fails, Edgeless Mesh will seamlessly substitute it with respect to the rules defined in the manifest.  

To keep things simple, Edgeless Mesh acts as certificate authority and issues one concise remote attestation statement for your whole distributed app. This can be used by anyone to verify the integrity of your distributed app. 

Edgeless Mesh is the service mesh for the age of confidential computing.

### Key features

:lock: Authentication and integrity verification of microservices

:package: Provisioning of certificates, configurations, and application artifacts

:globe_with_meridians: Remote attestation for the confidentiallity and integrity over the whole cluster.

![overview](docs/assets/overview.svg)

## Quickstart and documentation

See the [Getting Started Guide](TODO) to set up a distributed confidential-computing app in a few simple steps. 
For more comprehensive documentation, start with the [docs](TODO).

## Working in this repo

[`BUILD.md`](BUILD.md) includes general information on how to work in this repo.

## Get involved

* Follow [@EdgelessSystems][twitter] on Twitter.
* Join our [Slack][slack]

## Examples

### Hello World

We have two basic examples on how to build confidential applications with Edgeless Mesh.

* See [helloworld](../samples/helloworld/README.md) for how integrate Edgeless Mesh with your Golang application.
* See [helloc++](../samples/helloc++/README.md) for how integrate Edgeless Mesh with your C++ application.

### Confidential Emoji Voting

The popular [Linkerd][linkerd] service mesh uses the simple and fun scalable *emojivoto* app as the default demo. You can find our confidential variant [here][emojivoto]. Your emoji votes have never been safer!

## Roadmap 	:rocket:

Planned features include:

* Support for [Graphene][graphene], [SGX-LKL][sgx-lkl], and potentially other SGX software frameworks
* Distribution of the Control Plane to mitigate against a single point of failure

<!-- refs -->
[edgelessrt]: https://github.com/edgelesssys/edgelessrt
[emojivoto]: https://github.com/edgelesssys/emojivoto
[github-actions]: https://github.com/edgelesssys/coordinator/actions
[github-actions-badge]: https://github.com/edgelesssys/coordinator/workflows/Unit%20Tests/badge.svg
[go-report-card]: https://goreportcard.com/report/github.com/edgelesssys/mesh
[go-report-card-badge]: https://goreportcard.com/badge/github.com/edgelesssys/mesh
[graphene]: https://github.com/oscarlab/graphene
[license-badge]: https://img.shields.io/github/license/edgelesssys/mesh.svg
[linkerd]: https://linkerd.io
[sgx-lkl]: https://github.com/lsds/sgx-lkl
[slack]: http://edgelessmesh.slack.com
[twitter]: https://twitter.com/EdgelessSystems
