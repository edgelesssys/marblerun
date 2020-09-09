package main

import (
	"fmt"
	"log"
	"os"

	"github.com/edgelesssys/coordinator/coordinator/quote"
	"github.com/edgelesssys/coordinator/marble/marble"
)

const (
	Success             int = 0
	InternalError       int = -2
	AuthenticationError int = -4
)

func main() {}

func marbleTest(coordinationAddr, marbleType string) int {
	// set env vars
	if err := os.Setenv(marble.EdgCoordinatorAddr, coordinationAddr); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}
	if err := os.Setenv(marble.EdgMarbleType, marbleType); err != nil {
		log.Fatalf("failed to set env variable: %v", err)
		return InternalError
	}

	// call PreMain
	commonName := "marble" // Coordinator will assign an ID to us
	orgName := "Edgeless Systems GmbH"
	issuer := quote.NewERTIssuer()
	a, err := marble.NewAuthenticator(orgName, commonName, issuer)
	if err != nil {
		return InternalError
	}
	_, _, err = marble.PreMain(a)
	if err != nil {
		fmt.Println(err)
		return AuthenticationError
	}
	log.Println("Successfully authenticated with Coordinator!")
	return Success
}
