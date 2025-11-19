/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

// Package keyserver handles the distribution of key encryption keys (KEKs)
// to other Coordinator instances.
package keyserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/marblerun/coordinator/distributor/keyserver/keypb"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// KeyServer handles KEK distribution.
type KeyServer struct {
	keyEncryptionKey []byte
	qv               quote.Validator
	properties       quote.PackageProperties
	sealModeGetter   sealModeGetter

	log *zap.Logger

	keypb.UnimplementedAPIServer
}

// New creates a new KeyServer.
func New(acceptedProperties quote.PackageProperties, qv quote.Validator, sealModeGetter sealModeGetter, log *zap.Logger) *KeyServer {
	return &KeyServer{
		log:            log,
		qv:             qv,
		properties:     acceptedProperties,
		sealModeGetter: sealModeGetter,
	}
}

// Run starts the gRPC KeyServer.
func (s *KeyServer) Run(key []byte, port string) error {
	s.keyEncryptionKey = key

	// Create the TLS credentials
	// We require any client certificate to be present for quote validation
	tlsCfg := &tls.Config{}
	if !s.properties.Equal(quote.PackageProperties{}) { // not in simulation mode?
		var err error
		tlsCfg, err = enclave.CreateAttestationServerTLSConfig()
		if err != nil {
			return fmt.Errorf("failed to create TLS credentials: %s", err)
		}
	}
	tlsCfg.ClientAuth = tls.RequireAnyClientCert

	grpcServer := grpc.NewServer(grpc.Creds(credentials.NewTLS(tlsCfg)))
	keypb.RegisterAPIServer(grpcServer, s)

	s.log.Info("Starting key server", zap.String("port", port))
	lis, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", net.JoinHostPort("", port))
	if err != nil {
		return fmt.Errorf("failed to listen: %s", err)
	}
	return grpcServer.Serve(lis)
}

// GetKeyEncryptionKey returns the KEK if attestation passes.
func (s *KeyServer) GetKeyEncryptionKey(ctx context.Context, req *keypb.GetKeyEncryptionKeyRequest,
) (*keypb.GetKeyEncryptionKeyResponse, error) {
	peer, ok := peer.FromContext(ctx)
	if !ok {
		s.log.Error("Couldn't get peer info from context")
		return nil, status.Error(codes.Unauthenticated, "couldn't get peer info from context")
	}
	peerAddr := peer.Addr.String()

	s.log.Info("Received request for key encryption key, validating quote...", zap.String("peer", peerAddr))
	tlsInfo, ok := peer.AuthInfo.(credentials.TLSInfo)
	// the following check is just for safety (not for security)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		s.log.Error("Couldn't get new Coordinator instance TLS certificate", zap.String("peer", peerAddr))
		return nil, status.Error(codes.Unauthenticated, "couldn't get new Coordinator instance TLS certificate")
	}

	// Adapt and verify expected properties
	properties := s.properties
	if s.sealModeGetter.GetSealMode() == seal.ModeProductKey {
		// If we use the product key for sealing, we also do the key exchange based on ProductID/SignerID verification.
		s.log.Debug("Product key sealing is enabled, validating quote based on Product and Signer ID")
		properties.UniqueID = ""
		if properties.SignerID == "" || properties.ProductID == nil || properties.SecurityVersion == nil {
			return nil, status.Errorf(codes.Internal, "unexpected properties: %v", properties)
		}
	} else if properties.UniqueID == "" {
		return nil, status.Errorf(codes.Internal, "unexpected properties: %v", properties)
	}

	// Validate quote of new Coordinator instance
	if err := s.qv.Validate(req.Quote, tlsInfo.State.PeerCertificates[0].Raw, properties, quote.InfrastructureProperties{}); err != nil {
		s.log.Error("Quote validation failed", zap.Error(err), zap.String("peer", peerAddr))
		return nil, status.Error(codes.PermissionDenied, err.Error())
	}

	s.log.Info("Quote validation successful", zap.String("peer", peerAddr))
	return &keypb.GetKeyEncryptionKeyResponse{
		Key: s.keyEncryptionKey,
	}, nil
}

type sealModeGetter interface {
	GetSealMode() seal.Mode
}
