#!/usr/bin/env bash

if ! command -v az &> /dev/null
then
    echo "Azure CLI could not be found"
    echo "See Installation Guide @ https://docs.microsoft.com/en-us/cli/azure/install-azure-cli"
    exit
fi


if [ $# -lt 4 ];
then
    echo "Usage: $0 <az subscriptionID> <az resource group> <az cluster name> <az cluster #nodes>"
    exit 1
fi

SUBSCRIPTIONID=$1
RESOURCEGROUP=$2
CLUSTERNAME=$3
NODES=$4

UNIQUE_SUFFIX="$(cat /dev/urandom | tr -dc 'a-z0-9' | fold -w 16 | head -n 1)"
MARBLERUN_DNSNAME="marblerun-$UNIQUE_SUFFIX"

okStatus="\e[92m\u221A\e[0m"
warnStatus="\e[93m\u203C\e[0m"
failStatus="\e[91m\u00D7\e[0m"

# exit if command fails
set -e

#
# 1. Azure
#

# set azure account
echo "[*] Setting Azure subscription..."
az account set --subscription "$SUBSCRIPTIONID" > /dev/null

read -p "Do you want to create the cluster \"$CLUSTERNAME\"? (y/n) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]
then
    # create cluster
    echo "Creating cluster..."
    az aks create \
        --resource-group "$RESOURCEGROUP" \
        --name "$CLUSTERNAME" \
        --node-vm-size Standard_DC2s_v2 \
        --node-count "$NODES" \
        --enable-addon confcom \
	--enable-sgxquotehelper \
        --network-plugin azure \
        --vm-set-type VirtualMachineScaleSets \
        --aks-custom-headers usegen2vm=true > /dev/null
    echo -e "[$okStatus] Done"
fi

# get cluster credentials
echo "[*] Getting aks credentials"
az aks get-credentials --resource-group "$RESOURCEGROUP" --name "$CLUSTERNAME"
echo -e "[$okStatus] Done"
