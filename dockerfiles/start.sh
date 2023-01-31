#!/bin/bash

if [[ "${DCAP_LIBRARY}" == "intel" ]]
then
    apt-get install -qq libsgx-dcap-default-qpl > /dev/null 2>&1
else
    apt-get install -qq az-dcap-client > /dev/null 2>&1
fi

erthost coordinator-enclave.signed
