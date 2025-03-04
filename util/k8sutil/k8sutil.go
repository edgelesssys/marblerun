/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package k8sutil

import corev1 "k8s.io/api/core/v1"

// Resource tags for Kubernetes SGX device plugins.
const (
	IntelEpc       corev1.ResourceName = "sgx.intel.com/epc"
	IntelEnclave   corev1.ResourceName = "sgx.intel.com/enclave"
	IntelProvision corev1.ResourceName = "sgx.intel.com/provision"
	AzureEpc       corev1.ResourceName = "kubernetes.azure.com/sgx_epc_mem_in_MiB"
	AlibabaEpc     corev1.ResourceName = "alibabacloud.com/sgx_epc_MiB"
)

// GetEPCResourceLimit returns the amount of EPC to set for k8s deployments depending on the used sgx device plugin.
func GetEPCResourceLimit(resourceKey string) string {
	switch resourceKey {
	case AzureEpc.String():
		// azure device plugin expects epc in MiB
		return "10"
	case AlibabaEpc.String():
		// alibaba device plugin expects epc in MiB
		return "10"
	case IntelEpc.String():
		// intels device plugin expects epc as a k8s resource quantity
		return "10Mi"
	default:
		return "10"
	}
}
