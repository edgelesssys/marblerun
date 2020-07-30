package main

import (
	"fmt"
)

func coordinatormain(cwd, config string) {
	/*
		cfg := struct {
			DataPath              string
			DatabaseAddress       string
			APIAddress            string
			CertificateCommonName string
			Gomaxprocs            int
		}{
			"data",
			"",
			":8080",
			"localhost",
			0,
		}
		if config != "" {
			if err := json.Unmarshal([]byte(config), &cfg); err != nil {
				panic(err)
			}
		}

		if !filepath.IsAbs(cfg.DataPath) {
			cfg.DataPath = filepath.Join(cwd, cfg.DataPath)
		}
		mountData(cfg.DataPath)

		if cfg.Gomaxprocs > 2 {
			runtime.GOMAXPROCS(cfg.Gomaxprocs)
		}

		rt := ert{}
		db, err := db.NewTidb("/edb/tmp", "/edb/data", "255.0.0.1", cfg.DatabaseAddress, cfg.CertificateCommonName, &tidbLauncher{})
		if err != nil {
			panic(err)
		}
		core := core.NewCore(rt, db)
		mux := server.CreateServeMux(core)
		if err := core.StartDatabase(); err != nil {
			panic(err)
		}
		server.RunServer(mux, cfg.APIAddress, core.GetTLSConfig())
	*/
	fmt.Println("coordinator main")
}

/*
type tidbLauncher struct {
	running bool
}

func (t *tidbLauncher) Start() {
	if t.running {
		return
	}
	t.running = true
	launcherStarted = make(chan struct{})
	launcherStopped = make(chan struct{})
	go main()
	<-launcherStarted
	launcherStarted = nil
}

func (t *tidbLauncher) Stop() {
	if !t.running {
		return
	}
	t.running = false
	serverShutdown(false)
	<-launcherStopped
	launcherStopped = nil
}

type ert struct{}

func (r ert) GetRemoteReport(reportData []byte) ([]byte, error) {
	return ertenclave.GetRemoteReport(reportData)
}

func (r ert) GetProductSealKey() ([]byte, error) {
	// TODO use ertgolib
	return getProductSealKey()
}
*/
