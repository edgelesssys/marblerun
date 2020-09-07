package marbletest

import (
	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/premain"
)

func main() {}

func premainTest() int {
	// call preMain
	commonName := "marble"         // Coordinator will assign an ID to us
	issuer := quote.NewERTIssuer() // TODO: Use real issuer
	a, err := premain.NewAuthenticator(orgName, commonName, issuer)
	if err != nil {
		return -1
	}
	_, _, err := premain.PreMain(a)
	if err != nil {
		return -2
	}
	return 0
}
