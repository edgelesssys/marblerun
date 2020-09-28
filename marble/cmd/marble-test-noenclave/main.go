package main

import (
	"fmt"
	"log"
	"os"

	"github.com/edgelesssys/coordinator/marble/cmd/common"
	"github.com/edgelesssys/coordinator/marble/marble"
)

func main() {
	// call PreMain
	if err := marble.PreMainMock(); err != nil {
		panic(err)
	}
	ret := common.PremainTarget(len(os.Args), os.Args, os.Environ())
	if ret != 0 {
		panic(fmt.Errorf("premainTarget returned: %v", ret))
	}
	log.Println("Successfully authenticated with Coordinator!")
}
