// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package ertvalidator

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/edgelesssys/ego/attestation/tcbstatus"
	"github.com/edgelesssys/ego/enclave"
	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/internal/tcb"
	"go.uber.org/zap"
)

// ERTValidator is a Quote validator based on EdgelessRT.
type ERTValidator struct {
	log *zap.Logger
}

// NewERTValidator returns a new ERTValidator object.
func NewERTValidator(log *zap.Logger) *ERTValidator {
	return &ERTValidator{log: log}
}

// Validate validates an SGX quote using EdgelessRT.
func (v *ERTValidator) Validate(givenQuote []byte, cert []byte, pp quote.PackageProperties, _ quote.InfrastructureProperties) error {
	// Verify Quote
	accepted := pp.AcceptedTCBStatuses
	if len(accepted) == 0 {
		accepted = []string{tcbstatus.SWHardeningNeeded.String()}
	}
	report, err := enclave.VerifyRemoteReport(givenQuote)
	validity, err := tcb.CheckStatus(report.TCBStatus, err, accepted)
	if err != nil {
		return err
	}

	if report.TCBAdvisoriesErr != nil {
		v.log.Error("TCB Advisories", zap.Error(report.TCBAdvisoriesErr))
	}
	fmt.Println(report.TCBAdvisories)

	switch validity {
	case tcb.ValidityUnconditional:
	case tcb.ValidityConditional:
		v.log.Info("TCB level accepted by configuration",
			zap.String("packageProperties", pp.String()),
			zap.String("tcbStatus", report.TCBStatus.String()),
			zap.Strings("advisories", report.TCBAdvisories))
	default:
		v.log.Warn("TCB level invalid, but accepted by configuration",
			zap.String("packageProperties", pp.String()),
			zap.String("tcbStatus", report.TCBStatus.String()),
			zap.Strings("advisories", report.TCBAdvisories))
	}

	// Check that cert is equal
	hash := sha256.Sum256(cert)
	if !bytes.Equal(report.Data[:len(hash)], hash[:]) {
		return fmt.Errorf("hash(cert) != report.Data: %v != %v", hash, report.Data)
	}

	// Verify PackageProperties
	productID := binary.LittleEndian.Uint64(report.ProductID)
	reportedProps := quote.PackageProperties{
		UniqueID:        hex.EncodeToString(report.UniqueID),
		SignerID:        hex.EncodeToString(report.SignerID),
		Debug:           report.Debug,
		ProductID:       &productID,
		SecurityVersion: &report.SecurityVersion,
	}
	if !pp.IsCompliant(reportedProps) {
		return fmt.Errorf("PackageProperties not compliant:\nexpected: %s\ngot: %s", pp, reportedProps)
	}

	// TODO Verify InfrastructureProperties with information from OE Quote
	return nil
}

// ERTIssuer is a Quote issuer based on EdgelessRT.
type ERTIssuer struct{}

// NewERTIssuer returns a new ERTIssuer object.
func NewERTIssuer() *ERTIssuer {
	return &ERTIssuer{}
}

// Issue implements the Issuer interface.
func (i *ERTIssuer) Issue(cert []byte) ([]byte, error) {
	hash := sha256.Sum256(cert)
	return enclave.GetRemoteReport(hash[:])
}
