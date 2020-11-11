# Introduction

![logo](assets/mr_logo.svg)

Marblerun (or Edgeless MR) is a framework for creating distributed confidential-computing apps.

Build your confidential microservices with [Edgeless RT][edgelessrt], distribute them with Kubernetes on an SGX-enabled cluster, and let Marblerun take care of the rest. Deploy end-to-end secure and verifiable AI pipelines or crunch on sensitive big data in the cloud. Confidential computing at scale has never been easier.

Marblerun guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON. Marblerun verifies the integrity of services, bootstraps them, and sets up encrypted connections between them. If a node fails, Marblerun will seamlessly substitute it with respect to the rules defined in the manifest.

To keep things simple, Marblerun issues one concise remote attestation statement for your whole distributed app. This can be used by anyone to verify the integrity of your distributed app.

## Key features

* Authentication and integrity verification of microservices :lock:
* Provisioning of certificates, configurations, and application artifacts :package:
* Remote attestation for the confidentiallity and integrity over the whole cluster :globe_with_meridians:

## Overview

The following gives a high-level overview of a Marblerun-controlled cluster.

<img src="assets/overview.svg" alt="overview" width="600"/>

<!-- refs -->
[edgelessrt]: https://github.com/edgelesssys/edgelessrt
