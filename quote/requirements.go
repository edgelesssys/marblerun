package quote

// Requirements defines the requirements for validating a quote
// TODO: make less SGX specific
type Properties struct {
	Attributes []byte
	MRSigner   []byte
	MREnclave  []byte
	ISVProdID  uint16
	MinISVSVN  uint16
}

// Satisfies checks if a set of
func (r Requirements) Satisfies(other Requirements) bool
