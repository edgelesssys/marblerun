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
	Validate(quote []byte, message []byte, requirements Requirements) error
}

// Creator creats quotes
type Creator interface {
}
