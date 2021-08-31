// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ttime

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/cloudflare/roughtime/config"
	"github.com/cloudflare/roughtime/mjd"
	"github.com/cloudflare/roughtime/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoughtime(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	// Create mock server.
	server, configs, err := NewRoughtimeMockServer("127.0.0.1:2002")
	require.NoError(err)

	// Start server.
	server.Start()
	defer server.Close()

	// Create trusted time client.
	tt := TrustedTime{servers: configs}

	// Obtain time.
	rt, err := tt.Roughtime()
	require.NoError(err)

	// Compare times. Obviously, this is a bidirectional test that heavily
	// depends on the correctness of testing hardware's local time.
	// TODO(katexochen): Maybe remove this later.
	t1 := time.Now()
	t0, radius := rt.Now()
	diff := t1.Sub(t0)
	assert.LessOrEqual(diff, radius)
}

func TestNewTime(t *testing.T) {
	require := require.New(t)

	// Get a configuration.
	_, configs, err := NewRoughtimeMockServer("127.0.0.1:2002")
	require.NoError(err)

	// Check if NewTime returns a TrustedTime.
	time := NewTime(configs, nil)
	require.IsType(TrustedTime{}, time)
}

type MockRoughtimeServer struct {
	cert    []byte
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	netAddr *net.UDPAddr
	server  *net.UDPConn
}

func NewRoughtimeMockServer(addr string) (*MockRoughtimeServer, []config.Server, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, []config.Server{}, err
	}
	netAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, []config.Server{}, err
	}
	now := mjd.Now()
	yesterday := mjd.New(now.Day()-1, now.Microseconds())
	tomorrow := mjd.New(now.Day()+1, now.Microseconds())
	cert, err := protocol.CreateCertificate(yesterday, tomorrow, pub, priv)
	if err != nil {
		return nil, []config.Server{}, err
	}
	var configs []config.Server
	conf := config.Server{
		Name:          "RoughtimeMockServer",
		PublicKeyType: "ed25519",
		PublicKey:     pub,
		Addresses: []config.ServerAddress{
			{
				Protocol: "udp",
				Address:  addr,
			},
		},
	}
	configs = append(configs, conf)
	return &MockRoughtimeServer{
		cert:    cert,
		priv:    priv,
		pub:     pub,
		netAddr: netAddr,
	}, configs, nil
}

func (s *MockRoughtimeServer) Start() {
	var err error
	s.server, err = net.ListenUDP("udp", s.netAddr)
	if err != nil {
		return
	}
	go func() {
		query := make([]byte, 1280)
		for {
			queryLen, peer, err := s.server.ReadFrom(query)
			if err != nil {
				return
			}
			resp, err := protocol.CreateReply(query[:queryLen], mjd.Now(), 1000000, s.cert, s.priv)
			if err != nil {
				return
			}
			s.server.WriteTo(resp, peer)
		}
	}()
}

func (s *MockRoughtimeServer) Close() {
	s.server.Close()
}
