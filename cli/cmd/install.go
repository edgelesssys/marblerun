package cmd

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gofrs/flock"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
)

func newInstallCmd() *cobra.Command {
	var settings *cli.EnvSettings
	var domain string
	var chartPath string
	var simulation bool
	var noSgxDevicePlugin bool
	var meshServerPort int
	var clientServerPort int

	cmd := &cobra.Command{
		Use:   "install",
		Short: "Installs marblerun on a kubernetes cluster",
		Long:  `Installs marblerun on a kubernetes cluster`,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			settings = cli.New()
			hostname := domain
			sim := simulation
			noSgx := noSgxDevicePlugin
			path := chartPath
			clientPort := clientServerPort
			meshPort := meshServerPort
			return cliInstall(path, hostname, sim, noSgx, clientPort, meshPort, settings)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringVar(&domain, "domain", "localhost", "Sets the CNAME for the coordinator certificate")
	cmd.Flags().StringVar(&chartPath, "marblerun-chart-path", "", "Path to marblerun helm chart")
	cmd.Flags().BoolVar(&simulation, "simulation", false, "Set marblerun to start in simulation mode")
	cmd.Flags().BoolVar(&noSgxDevicePlugin, "no-sgx-device-plugin", false, "Disables the installation of an sgx device plugin")
	cmd.Flags().IntVar(&meshServerPort, "mesh-server-port", 25554, "Set the mesh server port. Needs to be configured to the same port as in the data-plane marbles")
	cmd.Flags().IntVar(&clientServerPort, "client-server-port", 25555, "Set the client server port. Needs to be configured to the same port as in your client tool stack")

	return cmd
}

// cliInstall installs marblerun on the cluster
func cliInstall(path string, hostname string, sim bool, noSgx bool, clientPort int, meshPort int, settings *cli.EnvSettings) error {
	actionConfig := new(action.Configuration)
	err := actionConfig.Init(settings.RESTClientGetter(), "marblerun", os.Getenv("HELM_DRIVER"), debug)

	// set overwrite values
	var vals map[string]interface{}
	if sim == true {
		// simulation mode, disable tolerations and resources, set simulation to 1
		vals = map[string]interface{}{
			"tolerations": nil,
			"coordinator": map[string]interface{}{
				"simulation": "1",
				"resources":  nil,
				"hostname":   hostname,
			},
		}
	} else {
		vals = map[string]interface{}{
			"coordinator": map[string]interface{}{
				"hostname": hostname,
			},
		}
	}
	if noSgx {
		// disable deployment of sgx-device-plugin pod
		vals["coordinator"].(map[string]interface{})["resources"] = nil
		vals["sgxDevice"] = map[string]interface{}{
			"start": false,
		}
	}
	vals["coordinator"].(map[string]interface{})["meshServerPort"] = meshPort
	vals["coordinator"].(map[string]interface{})["clientServerPort"] = clientPort

	// create helm installer
	installer := action.NewInstall(actionConfig)
	installer.CreateNamespace = true
	installer.Namespace = "marblerun"
	installer.ReleaseName = "marblerun-coordinator"

	if path == "" {
		// No chart was specified -> look for edgeless repository, if not present add it
		err = getRepo("edgeless", "https://helm.edgeless.systems/stable", settings)
		if err != nil {
			return err
		}
		path, err = installer.ChartPathOptions.LocateChart("edgeless/marblerun-coordinator", settings)
		if err != nil {
			return err
		}
	}
	chart, err := loader.Load(path)
	if err != nil {
		return err
	}

	err = chartutil.ValidateAgainstSchema(chart, vals)
	if err != nil {
		return err
	}

	_, err = installer.Run(chart, vals)
	if err != nil {
		return err
	}

	fmt.Printf("Marblerun installed successfully\n")
	return nil
}

// simplified repo_add from helm cli to add marblerun repo if it does not yet exist
func getRepo(name string, url string, settings *cli.EnvSettings) error {
	repoFile := settings.RepositoryConfig

	// Ensure the file directory exists as it is required for file locking
	err := os.MkdirAll(filepath.Dir(repoFile), os.ModePerm)
	if err != nil && !os.IsExist(err) {
		return err
	}

	// Acquire a file lock for process synchronization
	fileLock := flock.New(strings.Replace(repoFile, filepath.Ext(repoFile), ".lock", 1))
	lockCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	locked, err := fileLock.TryLockContext(lockCtx, time.Second)
	if err == nil && locked {
		defer fileLock.Unlock()
	}
	if err != nil {
		return err
	}

	b, err := ioutil.ReadFile(repoFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var f repo.File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return err
	}

	c := repo.Entry{
		Name: name,
		URL:  url,
	}

	if f.Has(name) {
		// Repository is already present on the systems, return nothing
		return nil
	}
	fmt.Printf("Did not find marblerun helm repository on system, adding now...\n")

	r, err := repo.NewChartRepository(&c, getter.All(settings))
	if err != nil {
		return err
	}

	if _, err := r.DownloadIndexFile(); err != nil {
		return errors.New("Chart repository cannot be reached")
	}

	f.Update(&c)

	if err := f.WriteFile(repoFile, 0644); err != nil {
		return err
	}
	fmt.Printf("%s has been added to your helm repositories\n", name)
	return nil
}

func debug(format string, v ...interface{}) {
}
