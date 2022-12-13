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
	// Uninitialized is the state of a Coordinator before it has been initialized.
	Uninitialized State = iota
	// Recovery indicates that the Coordinator requires manual recovery.
	Recovery
	// AcceptingManifest indicates that the Coordinator is waiting for a manifest.
	AcceptingManifest
	// AcceptingMarbles is the final state of the Coordinator.
	// It indicates that the Coordinator is ready accept marbles to activate.
	AcceptingMarbles
	// Max is the maximum value of the State enum.
	Max
)
