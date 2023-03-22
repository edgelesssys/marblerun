// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/edgelesssys/marblerun/cli/internal/rest"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestUpdate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update",
		Short: "Manage manifest updates for the MarbleRun Coordinator",
		Long:  "Manage manifest updates for the MarbleRun Coordinator.",
	}

	cmd.AddCommand(newUpdateApply())
	cmd.AddCommand(newUpdateAcknowledge())
	cmd.AddCommand(newUpdateCancel())
	cmd.AddCommand(newUpdateGet())
	return cmd
}

func newUpdateApply() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "apply <manifest.json> <IP:PORT>",
		Short: "Update the MarbleRun Coordinator with the specified manifest",
		Long: `
Update the MarbleRun Coordinator with the specified manifest.
An admin certificate specified in the original manifest is needed to verify the authenticity of the update manifest.
`,
		Example: "marblerun manifest update apply update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json",
		Args:    cobra.ExactArgs(2),
		RunE:    runUpdateApply,
	}

	cmd.Flags().StringP("cert", "c", "", "PEM encoded admin certificate file (required)")
	cmd.MarkFlagRequired("cert")
	cmd.Flags().StringP("key", "k", "", "PEM encoded admin key file (required)")
	cmd.MarkFlagRequired("key")

	return cmd
}

func newUpdateAcknowledge() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acknowledge <manifest.json> <IP:PORT>",
		Short: "Acknowledge a pending update for the MarbleRun Coordinator (Enterprise feature)",
		Long: `Acknowledge a pending update for the MarbleRun Coordinator (Enterprise feature).

In case of multi-party updates, the Coordinator will wait for all participants to acknowledge the update before applying it.
All participants must use the same manifest to acknowledge the pending update.
`,
		Example: "marblerun manifest update acknowledge update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json",
		Args:    cobra.ExactArgs(2),
		RunE:    runUpdateAcknowledge,
	}

	cmd.Flags().StringP("cert", "c", "", "PEM encoded admin certificate file (required)")
	cmd.MarkFlagRequired("cert")
	cmd.Flags().StringP("key", "k", "", "PEM encoded admin key file (required)")
	cmd.MarkFlagRequired("key")
	return cmd
}

func newUpdateCancel() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "cancel <IP:PORT>",
		Short:   "Cancel a pending manifest update for the MarbleRun Coordinator (Enterprise feature)",
		Long:    "Cancel a pending manifest update for the MarbleRun Coordinator (Enterprise feature).",
		Example: `marblerun manifest update cancel $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json`,
		Args:    cobra.ExactArgs(1),
		RunE:    runUpdateCancel,
	}

	cmd.Flags().StringP("cert", "c", "", "PEM encoded admin certificate file (required)")
	cmd.MarkFlagRequired("cert")
	cmd.Flags().StringP("key", "k", "", "PEM encoded admin key file (required)")
	cmd.MarkFlagRequired("key")
	return cmd
}

func newUpdateGet() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "get <IP:PORT>",
		Short:   "View a pending manifest update (Enterprise feature)",
		Long:    "View a pending manifest update (Enterprise feature).",
		Example: `marblerun manifest update get $MARBLERUN --era-config=era.json`,
		Args:    cobra.ExactArgs(1),
		RunE:    runUpdateGet,
	}

	cmd.Flags().StringP("output", "o", "", "Save output to file instead of printing to stdout")
	cmd.Flags().Bool("missing", false, "Display number of missing acknowledgements instead of the manifest")

	return cmd
}

func runUpdateApply(cmd *cobra.Command, args []string) error {
	manifestFile := args[0]
	hostname := args[1]

	client, err := rest.NewAuthenticatedClient(cmd, hostname)
	if err != nil {
		return err
	}

	manifest, err := loadManifestFile(file.New(manifestFile, afero.NewOsFs()))
	if err != nil {
		return err
	}

	cmd.Println("Successfully verified Coordinator, now uploading manifest")
	return cliManifestUpdateApply(cmd, manifest, client)
}

// cliManifestUpdate updates the Coordinators manifest using its rest api.
func cliManifestUpdateApply(cmd *cobra.Command, manifest []byte, client poster) error {
	_, err := client.Post(cmd.Context(), rest.UpdateEndpoint, rest.ContentJSON, bytes.NewReader(manifest))
	if err != nil {
		return fmt.Errorf("applying update: %w", err)
	}

	cmd.Println("Update manifest set successfully")
	return nil
}

func runUpdateAcknowledge(cmd *cobra.Command, args []string) error {
	manifestFile := args[0]
	hostname := args[1]

	client, err := rest.NewAuthenticatedClient(cmd, hostname)
	if err != nil {
		return err
	}

	manifest, err := loadManifestFile(file.New(manifestFile, afero.NewOsFs()))
	if err != nil {
		return err
	}

	cmd.Println("Successfully verified Coordinator")
	return cliManifestUpdateAcknowledge(cmd, manifest, client)
}

func cliManifestUpdateAcknowledge(cmd *cobra.Command, manifest []byte, client poster) error {
	resp, err := client.Post(cmd.Context(), rest.UpdateStatusEndpoint, rest.ContentJSON, bytes.NewReader(manifest))
	if err != nil {
		return fmt.Errorf("acknowledging update manifest: %w", err)
	}

	cmd.Printf("Acknowledgement successful: %s\n", resp)
	return nil
}

func runUpdateCancel(cmd *cobra.Command, args []string) error {
	hostname := args[0]

	client, err := rest.NewAuthenticatedClient(cmd, hostname)
	if err != nil {
		return err
	}

	cmd.Println("Successfully verified Coordinator")
	return cliManifestUpdateCancel(cmd, client)
}

func cliManifestUpdateCancel(cmd *cobra.Command, client poster) error {
	_, err := client.Post(cmd.Context(), rest.UpdateCancelEndpoint, "", http.NoBody)
	if err != nil {
		return fmt.Errorf("canceling update: %w", err)
	}
	cmd.Println("Cancellation successful")
	return nil
}

func runUpdateGet(cmd *cobra.Command, args []string) (retErr error) {
	hostname := args[0]

	outputFile, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	displayMissing, err := cmd.Flags().GetBool("missing")
	if err != nil {
		return err
	}
	client, err := rest.NewClient(cmd, hostname)
	if err != nil {
		return err
	}

	var out io.Writer
	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return err
		}
		defer func() {
			_ = file.Close()
			if retErr != nil {
				_ = os.Remove(outputFile)
			}
		}()
		out = file
	} else {
		out = cmd.OutOrStdout()
	}

	cmd.Println("Successfully verified Coordinator")
	return cliManifestUpdateGet(cmd.Context(), out, displayMissing, client)
}

func cliManifestUpdateGet(ctx context.Context, out io.Writer, displayMissing bool, client getter) error {
	resp, err := client.Get(ctx, rest.UpdateStatusEndpoint, http.NoBody)
	if err != nil {
		return fmt.Errorf("retrieving pending update manifest: %w", err)
	}

	var response string
	if displayMissing {
		msg := gjson.GetBytes(resp, "message")
		missingUsers := gjson.GetBytes(resp, "missingUsers")

		response = fmt.Sprintf("%s\nThe following users have not yet acknowledged the update: %s\n", msg.String(), missingUsers.String())
	} else {
		mnfB64 := gjson.GetBytes(resp, "manifest").String()
		mnf, err := base64.StdEncoding.DecodeString(mnfB64)
		if err != nil {
			return err
		}
		response = string(mnf)
	}
	fmt.Fprint(out, response)

	return nil
}
