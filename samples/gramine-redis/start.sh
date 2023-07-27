#!/bin/sh
set -e

if [ -n "${PCCS_ADDR}" ]; then
	PCCS_URL=https://${PCCS_ADDR}/sgx/certification/v4/
fi

# if PCCS_URL isn't set and we're on Azure, use Azure PCCS
if [ -z "${PCCS_URL}" ] && [ "$(cat /sys/devices/virtual/dmi/id/chassis_asset_tag)" = 7783-7084-3265-9085-8269-3286-77 ]; then
	PCCS_URL=https://global.acccache.azure.net/sgx/certification/v4/
	if [ -z "${PCCS_USE_SECURE_CERT}" ]; then
		PCCS_USE_SECURE_CERT=true
	fi
fi

if [ -z "${PCCS_USE_SECURE_CERT}" ]; then
	PCCS_USE_SECURE_CERT=false
fi

echo "PCCS_URL: ${PCCS_URL}"
echo "PCCS_USE_SECURE_CERT: ${PCCS_USE_SECURE_CERT}"

if [ "${PCCS_USE_SECURE_CERT}" != true ] && [ "${PCCS_USE_SECURE_CERT}" != false ] ; then
	echo 'PCCS_USE_SECURE_CERT must be "true" or "false"'
	exit 1
fi

sed -i "s/\"use_secure_cert\":.*/\"use_secure_cert\": ${PCCS_USE_SECURE_CERT}/" /etc/sgx_default_qcnl.conf
if [ -n "${PCCS_URL}" ]; then
	sed -i "s|\"pccs_url\":.*|\"pccs_url\": \"${PCCS_URL}\"|" /etc/sgx_default_qcnl.conf
fi

exec gramine-sgx /gramine/CI-Examples/redis/redis-server
