#!/bin/bash

if [[ "${DCAP_LIBRARY}" == "intel" ]]
then
    # rename the library installed by az-dcap-client
    mv /usr/lib/libdcap_quoteprov.so /usr/lib/libdcap_quoteprov.so.azure
    # create a link to the intel quote provider library
    mv /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1.intel /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1
    ln -s /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so.1 /usr/lib/x86_64-linux-gnu/libdcap_quoteprov.so
else
    export AZDCAP_DEBUG_LOG_LEVEL="${AZDCAP_DEBUG_LOG_LEVEL:=ERROR}"
fi

erthost coordinator-enclave.signed
