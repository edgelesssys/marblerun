// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package premain

import "encoding/binary"

func prependOEHeaderToRawQuote(rawQuote []byte) []byte {
	quoteHeader := make([]byte, 16)
	binary.LittleEndian.PutUint32(quoteHeader, 1)     // version
	binary.LittleEndian.PutUint32(quoteHeader[4:], 2) // OE_REPORT_TYPE_SGX_REMOTE
	binary.LittleEndian.PutUint64(quoteHeader[8:], uint64(len(rawQuote)))
	return append(quoteHeader, rawQuote...)
}
