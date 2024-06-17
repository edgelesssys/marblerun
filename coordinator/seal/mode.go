// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package seal

import "strings"

// Mode specifies how the data should be sealed.
type Mode uint

const (
	// ModeDisabled disables sealing and holds data in memory only.
	ModeDisabled Mode = iota
	// ModeProductKey enables sealing with the product key.
	ModeProductKey
	// ModeUniqueKey enables sealing with the unique key.
	ModeUniqueKey
)

// ModeFromString returns the Mode value for the given string.
func ModeFromString(mode string) Mode {
	switch {
	case mode == "", strings.EqualFold(mode, "ProductKey"):
		return ModeProductKey
	case strings.EqualFold(mode, "UniqueKey"):
		return ModeUniqueKey
	}
	return ModeDisabled
}
