// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

// State is the sequence of states a Coordinator may be in.
package state

// State is the sequence of states a Coordinator may be in.
type State int

const (
	Uninitialized State = iota
	Recovery
	AcceptingManifest
	AcceptingMarbles
	Max
)
