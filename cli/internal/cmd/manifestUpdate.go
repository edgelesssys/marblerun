/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/edgelesssys/marblerun/api"
	"github.com/edgelesssys/marblerun/cli/internal/certcache"
	"github.com/edgelesssys/marblerun/cli/internal/file"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
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
	addClientAuthFlags(cmd, cmd.Flags())

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
	addClientAuthFlags(cmd, cmd.Flags())

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
	addClientAuthFlags(cmd, cmd.Flags())

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

func runUpdateApply(cmd *cobra.Command, args []string) (err error) {
	manifestFile := args[0]
	hostname := args[1]
	fs := afero.NewOsFs()

	root, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), fs)
	if err != nil {
		return err
	}
	keyPair, cancel, err := certcache.LoadClientCert(cmd.Flags())
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, cancel())
	}()

	manifest, err := loadManifestFile(file.New(manifestFile, fs))
	if err != nil {
		return err
	}

	if err := api.ManifestUpdateApply(cmd.Context(), hostname, root, manifest, keyPair); err != nil {
		return fmt.Errorf("applying update: %w", err)
	}
	cmd.Println("Update manifest set successfully")
	return nil
}

func runUpdateAcknowledge(cmd *cobra.Command, args []string) (err error) {
	manifestFile := args[0]
	hostname := args[1]
	fs := afero.NewOsFs()

	root, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), fs)
	if err != nil {
		return err
	}
	keyPair, cancel, err := certcache.LoadClientCert(cmd.Flags())
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, cancel())
	}()

	manifest, err := loadManifestFile(file.New(manifestFile, fs))
	if err != nil {
		return err
	}

	missing, err := api.ManifestUpdateAcknowledge(cmd.Context(), hostname, root, manifest, keyPair)
	if err != nil {
		return fmt.Errorf("acknowledging update manifest: %w", err)
	}

	cmd.Println("Acknowledgement successful:")
	switch len(missing) {
	case 0:
		cmd.Println("All users have acknowledged the update manifest. Update successfully applied")
	case 1:
		cmd.Println("1 user still needs to acknowledge the update manifest")
	default:
		cmd.Printf("%d users still need to acknowledge the update manifest", len(missing))
	}
	return nil
}

func runUpdateCancel(cmd *cobra.Command, args []string) (err error) {
	hostname := args[0]
	fs := afero.NewOsFs()

	root, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), fs)
	if err != nil {
		return err
	}
	keyPair, cancel, err := certcache.LoadClientCert(cmd.Flags())
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, cancel())
	}()

	if err := api.ManifestUpdateCancel(cmd.Context(), hostname, root, keyPair); err != nil {
		return fmt.Errorf("canceling update: %w", err)
	}
	cmd.Println("Cancellation successful")
	return nil
}

func runUpdateGet(cmd *cobra.Command, args []string) (retErr error) {
	hostname := args[0]
	fs := afero.NewOsFs()

	outputFile, err := cmd.Flags().GetString("output")
	if err != nil {
		return err
	}
	displayMissing, err := cmd.Flags().GetBool("missing")
	if err != nil {
		return err
	}

	root, _, err := certcache.LoadCoordinatorCachedCert(cmd.Flags(), fs)
	if err != nil {
		return err
	}

	var out io.Writer
	if outputFile != "" {
		file, err := fs.Create(outputFile)
		if err != nil {
			return err
		}
		defer func() {
			_ = file.Close()
			if retErr != nil {
				_ = fs.Remove(outputFile)
			}
		}()
		out = file
	} else {
		out = cmd.OutOrStdout()
	}

	getManifestUpdate := func(ctx context.Context) ([]byte, []string, error) {
		return api.ManifestUpdateGet(ctx, hostname, root)
	}
	return cliManifestUpdateGet(cmd.Context(), out, displayMissing, getManifestUpdate)
}

func cliManifestUpdateGet(
	ctx context.Context, out io.Writer, displayMissing bool,
	getManifestUpdate func(context.Context) ([]byte, []string, error),
) error {
	manifest, missingUsers, err := getManifestUpdate(ctx)
	if err != nil {
		return fmt.Errorf("retrieving pending update manifest: %w", err)
	}

	var response string
	if displayMissing {
		response = fmt.Sprintf("The following users have not yet acknowledged the update: %s\n", missingUsers)
	} else {
		response = string(manifest)
	}
	fmt.Fprint(out, response)

	return nil
}
