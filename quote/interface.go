package quote

// Requirements defines the requirements for validating a quote
// TODO: make less SGX specific
type Requirements struct {
	Attributes []byte
	MRSigner   []byte
	MREnclave  []byte
	ISVProdID  uint16
	MinISVSVN  uint16
}

// Validator validates quotes
type Validator interface {
	// Validate validates a quote for a given message and requirements
	Validate(quote []byte, message []byte, requirements Requirements) error
}

// Issuer issues quotes
type Issuer interface {
	// Issue issues a quote for remote attestation for a given message
	Issue(message []byte) (quote []byte, err error)
}
