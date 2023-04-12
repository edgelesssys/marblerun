// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package helm

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/gofrs/flock"
	"gopkg.in/yaml.v2"
	"helm.sh/helm/v3/pkg/action"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
	"helm.sh/helm/v3/pkg/chartutil"
	"helm.sh/helm/v3/pkg/cli"
	"helm.sh/helm/v3/pkg/getter"
	"helm.sh/helm/v3/pkg/repo"
	"helm.sh/helm/v3/pkg/strvals"
)

type Options struct {
	Hostname            string
	DCAPQPL             string
	PCCSURL             string
	UseSecureCert       string
	AccessToken         string
	SGXResourceKey      string
	WebhookSettings     []string
	SimulationMode      bool
	CoordinatorRESTPort int
	CoordinatorGRPCPort int
}

// Client provides functionality to install and uninstall Helm charts.
type Client struct {
	config   *action.Configuration
	settings *cli.EnvSettings
}

// New initializes a new helm client.
func New() (*Client, error) {
	settings := cli.New()
	// settings.KubeConfig = kubeConfigPath

	actionConfig := &action.Configuration{}
	if err := actionConfig.Init(settings.RESTClientGetter(), Namespace, os.Getenv("HELM_DRIVER"), nopLog); err != nil {
		return nil, err
	}

	return &Client{
		config:   actionConfig,
		settings: settings,
	}, nil
}

// GetChart loads the helm chart from the given path or from the edgeless helm repo.
// This will add the edgeless helm repo if it is not already present on disk.
func (c *Client) GetChart(chartPath, version string, enterpriseRelease bool) (*chart.Chart, error) {
	if chartPath == "" {
		// No chart was specified -> add or update edgeless helm repo
		installer := action.NewInstall(c.config)
		installer.ChartPathOptions.Version = version

		err := c.getRepo(repoName, repoURI)
		if err != nil {
			return nil, fmt.Errorf("adding edgeless helm repo: %w", err)
		}

		// Enterprise chart is used if an access token is provided
		chartName := chartName
		if enterpriseRelease {
			chartName = chartNameEnterprise
		}

		chartPath, err = installer.ChartPathOptions.LocateChart(chartName, c.settings)
		if err != nil {
			return nil, fmt.Errorf("locating chart: %w", err)
		}
	}
	chart, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("loading chart from path %q: %w", chartPath, err)
	}
	return chart, nil
}

// UpdateValues merges the provided options with the default values of the chart.
func (c *Client) UpdateValues(options Options, chartValues map[string]interface{}) (map[string]interface{}, error) {
	stringValues := []string{}
	stringValues = append(stringValues, fmt.Sprintf("coordinator.meshServerPort=%d", options.CoordinatorGRPCPort))
	stringValues = append(stringValues, fmt.Sprintf("coordinator.clientServerPort=%d", options.CoordinatorRESTPort))

	if options.SimulationMode {
		// simulation mode, disable tolerations and resources, set simulation to true
		stringValues = append(stringValues,
			fmt.Sprintf("tolerations=%s", "null"),
			fmt.Sprintf("coordinator.simulation=%t", options.SimulationMode),
			fmt.Sprintf("coordinator.resources.limits=%s", "null"),
			fmt.Sprintf("coordinator.hostname=%s", options.Hostname),
			fmt.Sprintf("dcap=%s", "null"),
		)
	} else {
		stringValues = append(stringValues,
			fmt.Sprintf("coordinator.hostname=%s", options.Hostname),
			fmt.Sprintf("dcap.qpl=%s", options.DCAPQPL),
			fmt.Sprintf("dcap.pccsUrl=%s", options.PCCSURL),
			fmt.Sprintf("dcap.useSecureCert=%s", options.UseSecureCert),
		)

		// Helms value merge function will overwrite any preset values for "tolerations" if we set new ones here
		// To avoid this we set the new toleration for "resourceKey" and copy all preset tolerations
		needToleration := true
		idx := 0
		for _, toleration := range chartValues["tolerations"].([]interface{}) {
			if key, ok := toleration.(map[string]interface{})["key"]; ok {
				if key == options.SGXResourceKey {
					needToleration = false
				}
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].key=%v", idx, key))
			}
			if operator, ok := toleration.(map[string]interface{})["operator"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].operator=%v", idx, operator))
			}
			if effect, ok := toleration.(map[string]interface{})["effect"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].effect=%v", idx, effect))
			}
			if value, ok := toleration.(map[string]interface{})["value"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].value=%v", idx, value))
			}
			if tolerationSeconds, ok := toleration.(map[string]interface{})["tolerationSeconds"]; ok {
				stringValues = append(stringValues, fmt.Sprintf("tolerations[%d].tolerationSeconds=%v", idx, tolerationSeconds))
			}
			idx++
		}
		if needToleration {
			stringValues = append(stringValues,
				fmt.Sprintf("tolerations[%d].key=%s", idx, options.SGXResourceKey),
				fmt.Sprintf("tolerations[%d].operator=Exists", idx),
				fmt.Sprintf("tolerations[%d].effect=NoSchedule", idx),
			)
		}
	}

	// Configure enterprise access token
	if options.AccessToken != "" {
		coordinatorCfg, ok := chartValues["coordinator"].(map[string]interface{})
		if !ok {
			return nil, errors.New("coordinator not found in chart values")
		}
		repository, ok := coordinatorCfg["repository"].(string)
		if !ok {
			return nil, errors.New("coordinator.registry not found in chart values")
		}

		pullSecret := fmt.Sprintf(`{"auths":{"%s":{"auth":"%s"}}}`, repository, options.AccessToken)
		stringValues = append(stringValues, fmt.Sprintf("pullSecret.token=%s", base64.StdEncoding.EncodeToString([]byte(pullSecret))))
	}

	if len(options.WebhookSettings) > 0 {
		stringValues = append(stringValues, options.WebhookSettings...)
		stringValues = append(stringValues, fmt.Sprintf("marbleInjector.resourceKey=%s", options.SGXResourceKey))
	}

	finalValues := map[string]interface{}{}
	for _, val := range stringValues {
		if err := strvals.ParseInto(val, finalValues); err != nil {
			return nil, fmt.Errorf("parsing value %q into final values: %w", val, err)
		}
	}

	if !options.SimulationMode {
		setSGXValues(options.SGXResourceKey, finalValues, chartValues)
	}

	return finalValues, nil
}

// Install installs MarbleRun using the provided chart and values.
func (c *Client) Install(ctx context.Context, wait bool, chart *chart.Chart, values map[string]interface{}) error {
	installer := action.NewInstall(c.config)
	installer.Namespace = Namespace
	installer.ReleaseName = release
	installer.CreateNamespace = true
	installer.Wait = wait
	installer.Timeout = time.Minute * 5

	if err := chartutil.ValidateAgainstSchema(chart, values); err != nil {
		return err
	}

	_, err := installer.RunWithContext(ctx, chart, values)
	return err
}

// Uninstall removes the MarbleRun deployment from the cluster.
func (c *Client) Uninstall(wait bool) error {
	uninstaller := action.NewUninstall(c.config)
	uninstaller.Wait = wait
	uninstaller.Timeout = time.Minute * 5

	_, err := uninstaller.Run(release)
	return err
}

// getRepo is a simplified repo_add from helm cli to add MarbleRun repo if it does not yet exist.
// To make sure we use the newest chart we always download the needed index file.
func (c *Client) getRepo(name string, url string) error {
	repoFile := c.settings.RepositoryConfig

	// Ensure the file directory exists as it is required for file locking
	err := os.MkdirAll(filepath.Dir(repoFile), 0o755)
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

	b, err := os.ReadFile(repoFile)
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	var f repo.File
	if err := yaml.Unmarshal(b, &f); err != nil {
		return err
	}

	entry := &repo.Entry{
		Name: name,
		URL:  url,
	}

	r, err := repo.NewChartRepository(entry, getter.All(c.settings))
	if err != nil {
		return err
	}

	if _, err := r.DownloadIndexFile(); err != nil {
		return errors.New("chart repository cannot be reached")
	}

	f.Update(entry)

	if err := f.WriteFile(repoFile, 0o644); err != nil {
		return err
	}
	return nil
}

// setSGXValues sets the needed values for the coordinator as a map[string]interface.
// strvals can't parse keys which include dots, e.g. setting as a resource limit key "sgx.intel.com/epc" will lead to errors.
func setSGXValues(resourceKey string, values, chartValues map[string]interface{}) {
	values["coordinator"].(map[string]interface{})["resources"] = map[string]interface{}{
		"limits":   map[string]interface{}{},
		"requests": map[string]interface{}{},
	}

	var needNewLimit bool
	limit := k8sutil.GetEPCResourceLimit(resourceKey)

	// remove all previously set sgx resource limits
	if presetLimits, ok := chartValues["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{}); ok {
		for oldResourceKey := range presetLimits {
			// Make sure the key we delete is an unwanted sgx resource and not a custom resource or common resource (cpu, memory, etc.)
			if needsDeletion(oldResourceKey, resourceKey) {
				values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[oldResourceKey] = nil
				needNewLimit = true
			}
		}
	}

	// remove all previously set sgx resource requests
	if presetLimits, ok := chartValues["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["requests"].(map[string]interface{}); ok {
		for oldResourceKey := range presetLimits {
			if needsDeletion(oldResourceKey, resourceKey) {
				values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["requests"].(map[string]interface{})[oldResourceKey] = nil
				needNewLimit = true
			}
		}
	}

	// Set the new sgx resource limit, kubernetes will automatically set a resource request equal to the limit
	if needNewLimit {
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[resourceKey] = limit
	}

	// Make sure provision and enclave bit is set if the Intel plugin is used
	if resourceKey == k8sutil.IntelEpc.String() {
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[k8sutil.IntelProvision.String()] = 1
		values["coordinator"].(map[string]interface{})["resources"].(map[string]interface{})["limits"].(map[string]interface{})[k8sutil.IntelEnclave.String()] = 1
	}
}

// needsDeletion checks if an existing key of a helm chart should be deleted.
// Choice is based on the resource key of the used SGX device plugin.
func needsDeletion(existingKey, sgxKey string) bool {
	sgxResources := []string{
		k8sutil.AlibabaEpc.String(), k8sutil.AzureEpc.String(), k8sutil.IntelEpc.String(),
		k8sutil.IntelProvision.String(), k8sutil.IntelEnclave.String(),
	}

	switch sgxKey {
	case k8sutil.AlibabaEpc.String(), k8sutil.AzureEpc.String():
		// Delete all non Alibaba/Azure SGX resources depending on the used SGX device plugin
		return sgxKey != existingKey && keyInList(existingKey, sgxResources)
	case k8sutil.IntelEpc.String():
		// Delete all non Intel SGX resources depending on the used SGX device plugin
		// Keep Intel provision and enclave bit
		return keyInList(existingKey, []string{k8sutil.AlibabaEpc.String(), k8sutil.AzureEpc.String()})
	default:
		// Either no SGX plugin or a custom SGX plugin is used
		// Delete all known SGX resources
		return keyInList(existingKey, sgxResources)
	}
}

func keyInList(key string, list []string) bool {
	for _, l := range list {
		if key == l {
			return true
		}
	}
	return false
}

func nopLog(format string, v ...interface{}) {
}
