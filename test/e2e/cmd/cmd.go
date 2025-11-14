/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/state"
)

// Cmd handles CLI commands.
type Cmd struct {
	t       *testing.T
	cliPath string
}

// New returns a new Cmd.
func New(t *testing.T, cliPath string) (*Cmd, error) {
	t.Helper()

	realPath, err := exec.LookPath(cliPath)
	if err != nil {
		return nil, fmt.Errorf("checking for binary: %w", err)
	}

	return &Cmd{
		t:       t,
		cliPath: realPath,
	}, nil
}

// Run executes a CLI command.
func (c *Cmd) Run(ctx context.Context, args ...string) (string, error) {
	c.t.Helper()

	cmd := exec.CommandContext(ctx, c.cliPath, args...)
	out, err := cmd.CombinedOutput()
	c.t.Logf("%s: %s", cmd, out)
	if err != nil {
		return "", fmt.Errorf("executing command: %w: %s", err, out)
	}

	return string(out), nil
}

// GetStatus returns the status of the coordinator.
func (c *Cmd) GetStatus(ctx context.Context, addr string, flags ...string) (state.State, error) {
	// Run status command with insecure flag to ensure we can always connect to the Coordinator
	// even before setting a manifest.
	response, err := c.Run(ctx, append([]string{"status", addr, "--insecure"}, flags...)...)
	if err != nil {
		return -1, fmt.Errorf("getting status: %w", err)
	}

	var status state.State
	switch {
	case strings.Contains(response, fmt.Sprintf("%d: Coordinator is in recovery mode", state.Recovery)):
		status = state.Recovery
	case strings.Contains(response, fmt.Sprintf("%d: Coordinator is ready to accept a manifest", state.AcceptingManifest)):
		status = state.AcceptingManifest
	case strings.Contains(response, fmt.Sprintf("%d: Coordinator is running correctly and ready to accept marbles", state.AcceptingMarbles)):
		status = state.AcceptingMarbles
	default:
		return -1, fmt.Errorf("unexpected response: %s", response)
	}

	return status, nil
}
