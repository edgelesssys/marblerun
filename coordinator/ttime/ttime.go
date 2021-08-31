// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ttime

import (
	"time"

	"github.com/cloudflare/roughtime"
	"github.com/cloudflare/roughtime/config"
	"go.uber.org/zap"
)

// Time is an intrface that gives you the current time.
type Time interface {
	Now() time.Time
}

// NewTime returns a trusted or untrusted time, based on
// the servers you handed over.
func NewTime(servers []config.Server, logger *zap.Logger) Time {
	if len(servers) == 0 {
		return &UntrustedTime{}
	}
	return TrustedTime{servers: servers, zaplogger: logger}
}

// TrustedTime is a trusted time client.
// It uses the Roughtime protocol to obtain trusted timestamps from specified servers.
type TrustedTime struct {
	servers   []config.Server
	zaplogger *zap.Logger
}

// Roughtime parses a configuration file, requests a Roughtime from
// the first server that was parsed correctly, and returns this time.
func (t TrustedTime) Roughtime() (*roughtime.Roughtime, error) {
	rt, err := roughtime.Get(&t.servers[0], roughtime.DefaultQueryAttempts, roughtime.DefaultQueryTimeout, nil)
	if err != nil {
		return nil, err
	}
	return rt, nil
}

// Now returns a time.Time that was delivered by a Roughtime server.
// The radius of the Roughtime is ignored.
func (t TrustedTime) Now() time.Time {
	rt, err := t.Roughtime()
	if err != nil {
		if t.zaplogger != nil {
			t.zaplogger.Error("error getting Roughtime", zap.Error(err))
		}
		return time.Time{}
	}
	now, _ := rt.Now()
	return now
}

// UntrustedTime is just a wrapper around the default time package.
// The time package can't be trusted since it uses the host's time.
type UntrustedTime struct{}

// Now is a wrapper around time.Now().
func (u UntrustedTime) Now() time.Time {
	return time.Now()
}
