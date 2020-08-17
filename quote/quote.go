package quote

import (
	"bytes"
	"crypto/sha256"
	"errors"

	enc "github.com/edgelesssys/ertgolib/ertenclave"
	//"github.com/edgelesssys/erthost"
)

// ValidatorImpl is a quote validator
type ValidatorImpl struct {
}

// NewValidatorImpl .
func NewValidatorImpl() *ValidatorImpl {
	return &ValidatorImpl{}
}



// Validate implements the Validator interface
// Input:
// 		quote: received from Activate grpc call
//		message: raw cert from TLS context
//		pkg, infra: from manifest
func (m *ValidatorImpl) Validate(quote []byte, message []byte, pp PackageProperties, ip InfrastructureProperties) error {
	/*
		thought: VerifyRemoteReport probably calls IAS (could be observed)
		does this mean we should allways use VerifyRemoteReport, even if it's
		already clear the quote does not fit pp and ip? could leak information
	*/
	parsedReport, err := enc.VerifyRemoteReport(quote)

	//check message. message in quote contains hash of x.509 cert

	//copy from edbra::verifyReport
	hash := sha256.Sum256(message)
	if !bytes.Equal(parsedReport.Data[:len(hash)], hash[:]) {
		return errors.New("report data does not match the certificate's hash")
	}

	//check if quote fits pp and ip
	if err:=parsedReport.match(pp, ip); err!=nil{
		return err
	}
	return nil
}

//matches properties from the report to given PackageProperties and InfrastructureProperties
func (report enc.Report) match(pp PackageProperties, ip InfrastructureProperties) err {
	switch {
		report
		case report.SecurityVersion != pp.ISVSVN:
			return errors.New("SecurityVersion mismatch")
		case !bytes.(report.UniqueID, pp.MREnclave):
			return errors.New("UniqueID mismatch")
		case !bytes.Equal(report.SignerID, pp.MRSigner):
			return errors.New("SignerID mismatch")
		case !bytes.Equal(report.ProductID, pp.ISVProdID):
			return errors.New("ProductID mismatch")
		case report.Debug !=pp.allowDebug:
			return errors.New("Debug mismatch")
	}
	//TODO get information about infrastructure. either out of openEnclave or by manually parsing the quote?
	return nil
}

// IssuerImpl is a quote issuer for its own instance
type IssuerImpl struct{}

// NewIssuerImpl .
func NewIssuerImpl() *IssuerImpl {
	return &IssuerImpl{}
}

// Issue implements the Issuer interface. Argument message will be included in the report
func (m *IssuerImpl) Issue(message []byte) ([]byte, error) {
	//hash := sha256.Sum256(message)
	return enc.GetRemoteReport(message)
}
