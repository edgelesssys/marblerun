package coordinator

import (
	"encoding/json"
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

var exe = flag.String("e", "", "Coordinator executable")
var internAddr, externAddr string

func TestMain(m *testing.M) {
	flag.Parse()
	if *exe == "" {
		log.Fatalln("You must provide the path of the coordinator executable using th -e flag.")
	}
	if _, err := os.Stat(*exe); err != nil {
		log.Fatalln(err)
	}

	// get unused ports
	var listenerIntern, listenerExtern net.Listener
	listenerIntern, internAddr = getListenerAndAddr()
	listenerExtern, externAddr = getListenerAndAddr()
	listenerIntern.Close()
	listenerExtern.Close()
	os.Exit(m.Run())
}

func getListenerAndAddr() (net.Listener, string) {
	const localhost = "localhost:"

	listener, err := net.Listen("tcp", localhost)
	if err != nil {
		panic(err)
	}

	addr := listener.Addr().String()

	// addr contains IP address, we want hostname
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	return listener, localhost + port
}

// sanity test of the integration test environment
func TestTest(t *testing.T) {
	assert := assert.New(t)
	cfgFilename := createConfig()
	defer cleanupConfig(cfgFilename)
	assert.Nil(startCoordinator(cfgFilename).Kill())
}

type config struct {
	DataPath   string
	InternAddr string
	ExternAddr string
}

func createConfig() string {
	cfg := config{InternAddr: internAddr, ExternAddr: externAddr}

	var err error
	cfg.DataPath, err = ioutil.TempDir("", "")
	if err != nil {
		panic(err)
	}

	jsonCfg, err := json.Marshal(cfg)
	if err != nil {
		os.RemoveAll(cfg.DataPath)
		panic(err)
	}

	file, err := ioutil.TempFile("", "")
	if err != nil {
		os.RemoveAll(cfg.DataPath)
		panic(err)
	}

	name := file.Name()

	_, err = file.Write(jsonCfg)
	file.Close()
	if err != nil {
		os.Remove(name)
		os.RemoveAll(cfg.DataPath)
		panic(err)
	}

	return name
}

func cleanupConfig(filename string) {
	jsonCfg, err := ioutil.ReadFile(filename)
	os.Remove(filename)
	if err != nil {
		panic(err)
	}
	var cfg config
	if err := json.Unmarshal(jsonCfg, &cfg); err != nil {
		panic(err)
	}
	if err := os.RemoveAll(cfg.DataPath); err != nil {
		panic(err)
	}
}

func startCoordinator(configFilename string) *os.Process {
	cmd := exec.Command(*exe, "-c", configFilename)
	if err := cmd.Start(); err != nil {
		panic(err)
	}

	// Wait on the command so that cmd.ProcessState will be updated if the process dies.
	go cmd.Wait()

	log.Println("Coordinator starting ...")
	for {
		time.Sleep(10 * time.Millisecond)
		return cmd.Process
	}
}
