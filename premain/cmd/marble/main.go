package main

import (
	"fmt"
	"log"
	"os"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/premain"
)

const (
	Success             int = 0
	InternalError       int = -2
	AuthenticationError int = -4
)

func main() {}

func premainTest(coordinationAddr, marbleType string) int {
	// set env vars
	if err := os.Setenv(premain.EdgCoordinatorAddr, coordinationAddr); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}
	if err := os.Setenv(premain.EdgMarbleType, marbleType); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}

	// call preMain
	commonName := "marble" // Coordinator will assign an ID to us
	orgName := "Edgeless Systems GmbH"
	issuer := quote.NewERTIssuer()
	a, err := premain.NewAuthenticator(orgName, commonName, issuer)
	if err != nil {
		return InternalError
	}
	_, _, err = premain.PreMain(a)
	if err != nil {
		fmt.Println(err)
		return AuthenticationError
	}
	log.Println("Successfully authenticated with Coordinator!")
	return Success
}
