#!/bin/bash

if [[ "${DCAP_LIBRARY}" == "intel" ]]
then
    apt-get install -qq libsgx-dcap-default-qpl
else
    apt-get install -qq az-dcap-client
fi

erthost coordinator-enclave.signed
