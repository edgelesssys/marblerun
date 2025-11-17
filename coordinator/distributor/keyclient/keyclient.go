/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package keyclient requests key encryption keys (KEKs) from the keyserver.
// This allows new Coordinator instances to decrypt the sealed state.
package keyclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net"
	"slices"
	"strconv"
	"time"

	"github.com/edgelesssys/ego/attestation"
	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/marblerun/coordinator/constants"
	"github.com/edgelesssys/marblerun/coordinator/distributor/keyserver/keypb"
	"github.com/edgelesssys/marblerun/coordinator/kube"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	cutil "github.com/edgelesssys/marblerun/util"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/kubernetes"
	"k8s.io/utils/clock"
)

const (
	interval = 30 * time.Second
)

// KeyClient handles requesting keys.
type KeyClient struct {
	endpointGetter endpointGetter
	keyRequester   keyRequester

	tlsCfg   *tls.Config
	interval time.Duration
	clock    clock.WithTicker

	log *zap.Logger
}

// New creates a new KeyClient.
func New(acceptedProperties quote.PackageProperties, issuer quote.Issuer, log *zap.Logger) (*KeyClient, error) {
	client, err := kube.GetClient()
	if err != nil {
		return nil, err
	}

	clientCert, privKey, err := generateClientCertificate()
	if err != nil {
		return nil, fmt.Errorf("generating client certificate for Coordinator: %w", err)
	}

	tlsCfg := enclave.CreateAttestationClientTLSConfig(verifyReport(acceptedProperties), enclave.WithIgnoreTCBStatus())

	tlsCfg.Certificates = []tls.Certificate{
		{Certificate: [][]byte{clientCert}, PrivateKey: privKey},
	}

	return &KeyClient{
		endpointGetter: &k8sEndpointGetter{client: &kubeClient{client: client}},
		keyRequester:   &grpcKeyRequester{issuer: issuer},
		tlsCfg:         tlsCfg,
		interval:       interval,
		clock:          clock.RealClock{},
		log:            log,
	}, nil
}

// Run runs the key client routine.
// The client will try to request a key from all available Coordinator instances,
// until it succeeds, or the context is cancelled.
func (c *KeyClient) Run(ctx context.Context, serviceName, namespace string) []byte {
	c.log.Debug("Starting key encryption key request loop", zap.String("service", serviceName), zap.String("namespace", namespace), zap.Duration("interval", c.interval))
	ticker := c.clock.NewTicker(c.interval)
	for {
		defer ticker.Stop()

		endpoints, err := c.endpointGetter.getEndpoints(ctx, serviceName, namespace)
		if err != nil {
			c.log.Error("Failed to get endpoints", zap.Error(err))
		} else {
			c.log.Info("Requesting key from endpoints", zap.Strings("endpoints", endpoints))
			for _, endpoint := range endpoints {
				c.log.Debug("Requesting key from endpoint", zap.String("endpoint", endpoint))
				key, err := c.keyRequester.requestKey(ctx, endpoint, c.tlsCfg)
				if err == nil {
					c.log.Info("Received key from endpoint", zap.String("endpoint", endpoint))
					return key
				}
				c.log.Info("Failed to retrieve key from endpoint", zap.String("endpoint", endpoint), zap.Error(err))
			}
			c.log.Info("Failed to retrieve key from all endpoints, retrying...")
		}

		select {
		case <-ticker.C():
		case <-ctx.Done():
			return nil
		}
	}
}

type k8sEndpointGetter struct {
	client kubectl
}

// getEndpoints retrieves all endpoints of a Kubernetes service.
func (g *k8sEndpointGetter) getEndpoints(ctx context.Context, name, namespace string) ([]string, error) {
	endpoints, err := g.client.getEndpoints(ctx, name, namespace)
	if err != nil {
		return nil, err
	}
	var addresses []string
	for _, endpoint := range endpoints.Endpoints {
		for _, address := range endpoint.Addresses {
			for _, port := range endpoints.Ports {
				if port.Port == nil {
					continue
				}
				port := strconv.Itoa(int(*port.Port))
				addresses = append(addresses, net.JoinHostPort(address, port))
			}
		}
	}
	return addresses, nil
}

type grpcKeyRequester struct {
	issuer quote.Issuer
}

// requestKey requests a key from the endpoint.
func (r *grpcKeyRequester) requestKey(ctx context.Context, endpoint string, tlsCfg *tls.Config) ([]byte, error) {
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if len(tlsCfg.Certificates) == 0 {
		return nil, errors.New("missing client certificate")
	}

	quote, err := r.issuer.Issue(tlsCfg.Certificates[0].Certificate[0])
	if err != nil {
		return nil, err
	}

	keyClient := keypb.NewAPIClient(conn)
	key, err := keyClient.GetKeyEncryptionKey(ctx, &keypb.GetKeyEncryptionKeyRequest{Quote: quote})
	if err != nil {
		return nil, err
	}
	return key.Key, nil
}

type keyRequester interface {
	requestKey(ctx context.Context, endpoint string, tlsCfg *tls.Config) ([]byte, error)
}

type endpointGetter interface {
	getEndpoints(ctx context.Context, name, namespace string) ([]string, error)
}

type kubeClient struct {
	client kubernetes.Interface
}

func (c *kubeClient) getEndpoints(ctx context.Context, name, namespace string) (discoveryv1.EndpointSlice, error) {
	slices, err := c.client.DiscoveryV1().EndpointSlices(namespace).List(ctx, metav1.ListOptions{
		LabelSelector: labels.SelectorFromSet(labels.Set{"kubernetes.io/service-name": name}).String(),
	})
	if err != nil {
		return discoveryv1.EndpointSlice{}, err
	}
	if len(slices.Items) == 0 {
		return discoveryv1.EndpointSlice{}, fmt.Errorf("no endpoints found for service %s in namespace %s", name, namespace)
	}
	if len(slices.Items) > 1 {
		return discoveryv1.EndpointSlice{}, fmt.Errorf("multiple endpoint slices found for service %s in namespace %s", name, namespace)
	}
	return slices.Items[0], nil
}

type kubectl interface {
	getEndpoints(ctx context.Context, name, namespace string) (discoveryv1.EndpointSlice, error)
}

// verifyReport is a callback for [eclient.CreateAttestationClientTLSConfig].
// The function ensure the report of the server matches the accepted properties of the client.
func verifyReport(acceptedProperties quote.PackageProperties) func(report attestation.Report) error {
	return func(report attestation.Report) error {
		if report.Debug != acceptedProperties.Debug {
			return fmt.Errorf("Debug property mismatch: expected %t, got %t", acceptedProperties.Debug, report.Debug)
		}
		reportProdID := binary.LittleEndian.Uint64(report.ProductID)
		if reportProdID != *acceptedProperties.ProductID {
			return fmt.Errorf("ProductID mismatch: expected %d, got %d", *acceptedProperties.ProductID, reportProdID)
		}
		if report.SecurityVersion < *acceptedProperties.SecurityVersion {
			return fmt.Errorf("SecurityVersion mismatch: minimum version %d, got %d", *acceptedProperties.SecurityVersion, report.SecurityVersion)
		}
		if hex.EncodeToString(report.SignerID) != acceptedProperties.SignerID {
			return fmt.Errorf("SignerID mismatch: expected %s, got %s", acceptedProperties.SignerID, hex.EncodeToString(report.SignerID))
		}

		// Check TCB status
		// Always accept UpToDate, as this is the default value.
		if report.TCBStatus != tcbstatus.UpToDate {
			if !slices.Contains(acceptedProperties.AcceptedTCBStatuses, report.TCBStatus.String()) {
				return fmt.Errorf("invalid TCB Status: %s", report.TCBStatus)
			}
		}

		return nil
	}
}

// generateClientCertificate creates a self signed client certificate for the key client.
func generateClientCertificate() ([]byte, *ecdsa.PrivateKey, error) {
	privk, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(math.MaxInt64)

	serialNumber, err := cutil.GenerateCertificateSerialNumber()
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		Subject: pkix.Name{
			CommonName: constants.CoordinatorName,
		},
		SerialNumber: serialNumber,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}

	certRaw, err := x509.CreateCertificate(rand.Reader, &template, &template, &privk.PublicKey, privk)
	if err != nil {
		return nil, nil, err
	}
	return certRaw, privk, nil
}
