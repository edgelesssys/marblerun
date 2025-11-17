/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package keyserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/distributor/keyserver/keypb"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/seal"
	"github.com/stretchr/testify/assert"
	"go.uber.org/goleak"
	"go.uber.org/zap/zaptest"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m)
}

func TestKeyServer(t *testing.T) {
	testCases := map[string]struct {
		clientAuth     credentials.TLSInfo
		sealMode       seal.Mode
		quote          []byte
		wantQuote      []byte
		properties     quote.PackageProperties
		wantProperties quote.PackageProperties
		wantErr        bool
	}{
		"success": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			quote:          []byte("quote"),
			wantQuote:      []byte("quote"),
			properties:     quote.PackageProperties{UniqueID: "unique-id"},
			wantProperties: quote.PackageProperties{UniqueID: "unique-id"},
		},
		"success in UniqueKey Mode": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			sealMode:       seal.ModeUniqueKey,
			quote:          []byte("quote"),
			wantQuote:      []byte("quote"),
			properties:     quote.PackageProperties{UniqueID: "unique-id"},
			wantProperties: quote.PackageProperties{UniqueID: "unique-id"},
		},
		"success in ProductKey mode": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			sealMode:       seal.ModeProductKey,
			quote:          []byte("quote"),
			wantQuote:      []byte("quote"),
			properties:     quote.PackageProperties{UniqueID: "will be ignored", SignerID: "signer-id", ProductID: new(uint64), SecurityVersion: new(uint)},
			wantProperties: quote.PackageProperties{SignerID: "signer-id", ProductID: new(uint64), SecurityVersion: new(uint)},
		},
		"no client cert": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{},
			},
			quote:          []byte("quote"),
			wantQuote:      []byte("quote"),
			properties:     quote.PackageProperties{UniqueID: "unique-id"},
			wantProperties: quote.PackageProperties{UniqueID: "unique-id"},
			wantErr:        true,
		},
		"invalid quote": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			quote:          []byte("wrong-quote"),
			wantQuote:      []byte("quote"),
			properties:     quote.PackageProperties{UniqueID: "unique-id"},
			wantProperties: quote.PackageProperties{UniqueID: "unique-id"},
			wantErr:        true,
		},
		"invalid properties": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			quote:          []byte("quote"),
			wantQuote:      []byte("quote"),
			properties:     quote.PackageProperties{UniqueID: "wrong-id"},
			wantProperties: quote.PackageProperties{UniqueID: "unique-id"},
			wantErr:        true,
		},
		"missing UniqueID": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			quote:          []byte("quote"),
			wantQuote:      []byte("quote"),
			properties:     quote.PackageProperties{SignerID: "signer-id", ProductID: new(uint64), SecurityVersion: new(uint)},
			wantProperties: quote.PackageProperties{SignerID: "signer-id", ProductID: new(uint64), SecurityVersion: new(uint)},
			wantErr:        true,
		},
		"missing SignerID": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			sealMode:   seal.ModeProductKey,
			quote:      []byte("quote"),
			wantQuote:  []byte("quote"),
			properties: quote.PackageProperties{ProductID: new(uint64), SecurityVersion: new(uint)},
			wantErr:    true,
		},
		"missing ProductID": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			sealMode:   seal.ModeProductKey,
			quote:      []byte("quote"),
			wantQuote:  []byte("quote"),
			properties: quote.PackageProperties{SignerID: "signer-id", SecurityVersion: new(uint)},
			wantErr:    true,
		},
		"missing SecurityVersion": {
			clientAuth: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{{}}, // one cert
				},
			},
			sealMode:   seal.ModeProductKey,
			quote:      []byte("quote"),
			wantQuote:  []byte("quote"),
			properties: quote.PackageProperties{SignerID: "signer-id", ProductID: new(uint64)},
			wantErr:    true,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)

			key := []byte("key")
			qv := quote.NewMockValidator()
			s := KeyServer{
				keyEncryptionKey: key,
				properties:       tc.properties,
				sealModeGetter:   &stubSealModeGetter{tc.sealMode},
				log:              zaptest.NewLogger(t),
				qv:               qv,
			}
			qv.AddValidQuote(tc.wantQuote, nil, tc.wantProperties, quote.InfrastructureProperties{})

			p := &peer.Peer{
				Addr:     &stubAddr{},
				AuthInfo: tc.clientAuth,
			}
			ctx := peer.NewContext(context.Background(), p)
			res, err := s.GetKeyEncryptionKey(ctx, &keypb.GetKeyEncryptionKeyRequest{Quote: tc.quote})
			if tc.wantErr {
				assert.Error(err)
				return
			}
			assert.NoError(err)
			assert.Equal(key, res.Key)
		})
	}
}

type stubSealModeGetter struct {
	mode seal.Mode
}

func (s stubSealModeGetter) GetSealMode() seal.Mode {
	return s.mode
}

type stubAddr struct{}

func (s stubAddr) Network() string {
	return "unit-test"
}

func (s stubAddr) String() string {
	return "unit-test"
}
