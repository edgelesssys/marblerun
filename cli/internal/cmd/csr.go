// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"time"

	certv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

// certificateInterface provides the interface for certificate handlers.
type certificateInterface interface {
	// get the signed certificate
	get(context.Context) ([]byte, error)
	// set the caBundle field for the helm chart
	setCaBundle() ([]string, error)
	// sign the certificate
	signRequest(context.Context) error
	getKey() *rsa.PrivateKey
}

// certificateV1 acts as a handler for generating signed certificates.
type certificateV1 struct {
	kubeClient kubernetes.Interface
	privKey    *rsa.PrivateKey
	csr        *certv1.CertificateSigningRequest
	timeout    int
}

// newCertificateV1 creates a certificate handler using the certificatesv1 kubernetes api.
func newCertificateV1(kubeClient kubernetes.Interface) (*certificateV1, error) {
	crt := &certificateV1{kubeClient: kubeClient}
	crt.timeout = 10

	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed creating rsa private key: %w", err)
	}

	crt.privKey = privKey

	csrPEM, err := createCSR(privKey)
	if err != nil {
		return nil, err
	}

	// create the k8s certificate request which bundles the x509 csr
	certificateRequest := &certv1.CertificateSigningRequest{
		ObjectMeta: metav1.ObjectMeta{
			Name: webhookName,
		},
		Spec: certv1.CertificateSigningRequestSpec{
			Request:    pem.EncodeToMemory(csrPEM),
			SignerName: "kubernetes.io/kubelet-serving",
			// usages have to match usages defined in the x509 csr
			Usages: []certv1.KeyUsage{
				"key encipherment", "digital signature", "server auth",
			},
		},
	}
	crt.csr = certificateRequest

	return crt, nil
}

// get returns the certificate signed by the kubernetes api server.
func (crt *certificateV1) get(ctx context.Context) ([]byte, error) {
	csr, err := crt.kubeClient.CertificatesV1().CertificateSigningRequests().Get(ctx, webhookName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	return csr.Status.Certificate, nil
}

// setCaBundle sets the CABundle field to the clusters CABundle.
func (crt *certificateV1) setCaBundle() ([]string, error) {
	path := os.Getenv(clientcmd.RecommendedConfigPathEnvVar)
	if path == "" {
		homedir, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		path = filepath.Join(homedir, clientcmd.RecommendedHomeDir, clientcmd.RecommendedFileName)
	}

	kubeConfig, err := clientcmd.BuildConfigFromFlags("", path)
	if err != nil {
		return nil, err
	}

	var caBundle string

	if len(kubeConfig.CAData) > 0 {
		caBundle = base64.StdEncoding.EncodeToString(kubeConfig.CAData)
	} else if len(kubeConfig.CAFile) > 0 {
		fileData, err := os.ReadFile(kubeConfig.CAFile)
		if err != nil {
			return nil, err
		}
		caBundle = base64.StdEncoding.EncodeToString(fileData)
	} else {
		return nil, fmt.Errorf("reading CAData or CAFile from kube-config: %s", path)
	}

	injectorVals := []string{
		fmt.Sprintf("marbleInjector.start=%t", true),
		fmt.Sprintf("marbleInjector.CABundle=%s", caBundle),
	}

	return injectorVals, nil
}

// signRequest performs a certificate signing request to the api server and approves it.
func (crt *certificateV1) signRequest(ctx context.Context) error {
	// send the csr to the k8s api server for signing
	certReturn, err := crt.kubeClient.CertificatesV1().CertificateSigningRequests().Create(ctx, crt.csr, metav1.CreateOptions{})
	if err != nil {
		return err
	}

	if err := waitForResource(webhookName, crt.kubeClient, crt.timeout, func(name string, client kubernetes.Interface) bool {
		_, err := client.CertificatesV1().CertificateSigningRequests().Get(ctx, name, metav1.GetOptions{})
		return err == nil
	}); err != nil {
		return err
	}

	// approve of the signing, the users performing the install have to be allowed to approve certificates
	// e.g. if they can use kubectl certificate approve $csr_name, then this should also work
	certReturn.Status.Conditions = append(certReturn.Status.Conditions, certv1.CertificateSigningRequestCondition{
		Type:           certv1.RequestConditionType(string(certv1.CertificateApproved)),
		Status:         corev1.ConditionTrue,
		Reason:         "MarbleRunInstall",
		Message:        "This CSR was automatically approved after creation with marblerun install.",
		LastUpdateTime: metav1.Now(),
	})

	_, err = crt.kubeClient.CertificatesV1().CertificateSigningRequests().UpdateApproval(ctx, webhookName, certReturn, metav1.UpdateOptions{})
	if err != nil {
		return err
	}

	return waitForResource(webhookName, crt.kubeClient, crt.timeout, func(name string, client kubernetes.Interface) bool {
		csr, err := client.CertificatesV1().CertificateSigningRequests().Get(ctx, webhookName, metav1.GetOptions{})
		if err != nil {
			return false
		}
		if len(csr.Status.Certificate) <= 0 {
			return false
		}
		return true
	})
}

// getKey returns the private key of the webhook server.
func (crt *certificateV1) getKey() *rsa.PrivateKey {
	return crt.privKey
}

// createCSR creates a x509 certificate signing request.
func createCSR(privKey *rsa.PrivateKey) (*pem.Block, error) {
	subj := pkix.Name{
		CommonName:   "system:node:marble-injector.marblerun.svc",
		Organization: []string{"system:nodes"},
	}

	// set KeyUsage extensions. See RFC 5280, Section 4.2.1.3 and Section 4.2.1.12
	extendedUsage := pkix.Extension{
		// id-kp (Extended Key Usage) object identifier
		Id:       asn1.ObjectIdentifier{2, 5, 29, 37},
		Critical: true,
		// id-kp-serverAuth object identifier
		Value: []byte{0x30, 0xa, 0x6, 0x8, 0x2b, 0x6, 0x1, 0x5, 0x5, 0x7, 0x3, 0x1},
	}
	keyUsage := pkix.Extension{
		// id-ce-keyUsage object identifier
		Id:       asn1.ObjectIdentifier{2, 5, 29, 15},
		Critical: true,
		// bit string for key encipherment, digital signature
		Value: []byte{0x3, 0x2, 0x5, 0xa0},
	}

	// create a x509 certificate request
	template := &x509.CertificateRequest{
		Subject:            subj,
		SignatureAlgorithm: x509.SHA256WithRSA,
		Extensions:         []pkix.Extension{extendedUsage, keyUsage},
		DNSNames:           []string{"marble-injector.marblerun.svc"},
	}

	csrRaw, err := x509.CreateCertificateRequest(rand.Reader, template, privKey)
	if err != nil {
		return nil, err
	}

	csrPEM := &pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrRaw,
	}

	return csrPEM, nil
}

// calls to the CertificateSigningRequests interface are non blocking, we use this function
// to check if a resource has been created and can be used.
func waitForResource(name string, kubeClient kubernetes.Interface, timeout int, resourceCheck func(string, kubernetes.Interface) bool) error {
	for i := 0; i < timeout; i++ {
		if resourceCheck(name, kubeClient) {
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("certificate signing request was not updated after %d attempts. Giving up", timeout)
}
