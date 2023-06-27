---
slug: /
---

# Welcome to MarbleRun

MarbleRun is a framework for creating distributed confidential computing apps.

Build your confidential microservices with [EGo, Gramine, or another runtime](features/runtimes.md), distribute them with Kubernetes on an SGX-enabled cluster, and let MarbleRun take care of the rest. Deploy end-to-end secure and verifiable AI pipelines or crunch on sensitive big data in the cloud. Confidential computing at scale has never been easier.

MarbleRun guarantees that the topology of your distributed app adheres to a manifest specified in simple JSON. MarbleRun verifies the integrity of services, bootstraps them, and sets up encrypted connections between them. If a node fails, MarbleRun will seamlessly substitute it with respect to the rules defined in the manifest.

To keep things simple, MarbleRun issues one concise remote-attestation statement for your whole distributed app. This can be used by anyone to verify the integrity of your distributed app.

## Key features

🔒 Authentication and integrity verification of microservices based on the manifest


🔑 Secrets management for microservices


📃 Provisioning of certificates, configurations, and parameters


🔬 Remote attestation of the entire cluster

## Overview

Logically, MarbleRun consists of two parts, the control plane called *Coordinator* and the data plane called *Marbles*.
The Coordinator needs to be deployed once in your cluster and the Marble layer needs to be integrated with each service.
MarbleRun is configured with a simple JSON document called the *manifest*.
It specifies the topology of the distributed app, the infrastructure properties, and provides configuration parameters for each service.

![overview](_media/overview.svg)
