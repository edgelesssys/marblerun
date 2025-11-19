#!/bin/bash

exec env EDG_KUBERNETES_SERVICE_HOST="${KUBERNETES_SERVICE_HOST}" \
    env EDG_KUBERNETES_SERVICE_PORT="${KUBERNETES_SERVICE_PORT}" \
    erthost coordinator-enclave.signed
