/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package helm

import (
	"context"
	"fmt"
	"testing"
	"time"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/loader"
	"helm.sh/helm/v4/pkg/cli"
	"helm.sh/helm/v4/pkg/kube"
)

// Helm handles helm actions.
type Helm struct {
	t *testing.T

	config *action.Configuration
}

// New initializes a new Helm configuration.
func New(t *testing.T, kubeConfigPath, namespace string) (*Helm, error) {
	settings := cli.New()
	settings.KubeConfig = kubeConfigPath
	settings.SetNamespace(namespace)

	actionConfig := &action.Configuration{}

	if err := actionConfig.Init(settings.RESTClientGetter(), settings.Namespace(), "secret"); err != nil {
		return nil, fmt.Errorf("initializing helm: %w", err)
	}

	return &Helm{
		t:      t,
		config: actionConfig,
	}, nil
}

// InstallChart installs the MarbleRun helm chart and waits for all pods to be ready.
func (h *Helm) InstallChart(
	ctx context.Context, releaseName, namespace, chartPath string, replicas int, timeout time.Duration, extraValues map[string]any,
) (func(), error) {
	h.t.Helper()

	install := action.NewInstall(h.config)
	install.Namespace = namespace
	install.ReleaseName = releaseName
	install.Timeout = timeout
	install.WaitForJobs = true
	install.WaitStrategy = kube.StatusWatcherStrategy

	// Load the chart from the path.
	chart, err := loader.Load(chartPath)
	if err != nil {
		return nil, fmt.Errorf("loading chart: %w", err)
	}

	values := map[string]any{
		"coordinator": map[string]any{
			"distributedDeployment": true,
			"replicas":              replicas,
		},
		"pullSecret": map[string]any{
			"name": "access-token",
		},
	}
	values = mergeMaps(values, extraValues)

	if _, err = install.RunWithContext(ctx, chart, values); err != nil {
		return nil, fmt.Errorf("installing chart: %w", err)
	}

	uninstall := func() {
		if _, err := action.NewUninstall(h.config).Run(releaseName); err != nil {
			h.t.Logf("Uninstalling chart: %s", err)
		}
	}

	return uninstall, nil
}

func mergeMaps(a, b map[string]any) map[string]any {
	out := make(map[string]any, len(a))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		if v, ok := v.(map[string]any); ok {
			if bv, ok := out[k]; ok {
				if bv, ok := bv.(map[string]any); ok {
					out[k] = mergeMaps(bv, v)
					continue
				}
			}
		}
		out[k] = v
	}
	return out
}
