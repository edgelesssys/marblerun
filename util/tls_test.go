// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package util

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractIPsFromAltNames(t *testing.T) {
	testCases := map[string]struct {
		altNames     []string
		wantIPs      []net.IP
		wantDNSNames []string
	}{
		"empty": {
			altNames:     []string{},
			wantIPs:      []net.IP{},
			wantDNSNames: []string{},
		},
		"only IPs": {
			altNames:     []string{"192.0.2.1", "192.0.2.15"},
			wantIPs:      []net.IP{net.ParseIP("192.0.2.1"), net.ParseIP("192.0.2.15")},
			wantDNSNames: []string{},
		},
		"only DNS names": {
			altNames:     []string{"foo.bar", "example.com"},
			wantIPs:      []net.IP{},
			wantDNSNames: []string{"foo.bar", "example.com"},
		},
		"mixed": {
			altNames:     []string{"192.0.2.1", "foo.bar"},
			wantIPs:      []net.IP{net.ParseIP("192.0.2.1")},
			wantDNSNames: []string{"foo.bar"},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			gotIPs, gotDNSNames := ExtractIPsFromAltNames(tc.altNames)
			assert.ElementsMatch(tc.wantIPs, gotIPs)
			assert.ElementsMatch(tc.wantDNSNames, gotDNSNames)
		})
	}
}
