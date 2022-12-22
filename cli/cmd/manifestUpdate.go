// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

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
		Short: "Updates the MarbleRun Coordinator with the specified manifest",
		Long: `
Updates the MarbleRun Coordinator with the specified manifest.
An admin certificate specified in the original manifest is needed to verify the authenticity of the update manifest.
`,
		Example: "marblerun manifest update apply update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]
			hostName := args[1]

			client, err := authenticatedClient(cmd, hostName)
			if err != nil {
				return err
			}

			// Load manifest
			manifest, err := loadManifestFile(manifestFile)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified Coordinator, now uploading manifest")
			return cliManifestUpdate(manifest, hostName, client)
		},
		SilenceUsage: true,
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

In case of multi party updates, the Coordinator will wait for all participants to acknowledge the update before applying it.
All participants must use the same manifest to acknowledge the pending update.
`,
		Example: "marblerun manifest update acknowledge update-manifest.json $MARBLERUN --cert=admin-cert.pem --key=admin-key.pem --era-config=era.json",
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			manifestFile := args[0]
			hostName := args[1]

			client, err := authenticatedClient(cmd, hostName)
			if err != nil {
				return err
			}

			// Load manifest
			manifest, err := loadManifestFile(manifestFile)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified Coordinator")
			return cliManifestUpdateAcknowledge(manifest, hostName, client)
		},
		SilenceUsage: true,
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
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]

			client, err := authenticatedClient(cmd, hostName)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified Coordinator")
			return cliManifestUpdateCancel(hostName, client)
		},
		SilenceUsage: true,
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
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]

			out, err := cmd.Flags().GetString("output")
			if err != nil {
				return err
			}

			caCert, err := verifyCoordinator(hostName, eraConfig, insecureEra, acceptedTCBStatuses)
			if err != nil {
				return err
			}
			client, err := restClient(caCert, nil)
			if err != nil {
				return err
			}

			fmt.Println("Successfully verified Coordinator")
			return cliManifestUpdateGet(out, hostName, client)
		},
		SilenceUsage: true,
	}

	cmd.Flags().StringP("output", "o", "", "Save output to file instead of printing to stdout")

	return cmd
}

func authenticatedClient(cmd *cobra.Command, hostName string) (*http.Client, error) {
	caCert, err := verifyCoordinator(hostName, eraConfig, insecureEra, acceptedTCBStatuses)
	if err != nil {
		return nil, err
	}

	fmt.Println("Coordinator verified")
	clientAdminCert, err := cmd.Flags().GetString("cert")
	if err != nil {
		return nil, err
	}
	clientAdminKey, err := cmd.Flags().GetString("key")
	if err != nil {
		return nil, err
	}

	fmt.Println("Loading client certificate")
	clCert, err := tls.LoadX509KeyPair(clientAdminCert, clientAdminKey)
	if err != nil {
		return nil, err
	}

	fmt.Println("Creating client")
	client, err := restClient(caCert, &clCert)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// cliManifestUpdate updates the Coordinators manifest using its rest api.
func cliManifestUpdate(manifest []byte, host string, client *http.Client) error {
	url := url.URL{Scheme: "https", Host: host, Path: "update"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url.String(), bytes.NewReader(manifest))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Println("Update manifest set successfully")
	case http.StatusBadRequest:
		return fmt.Errorf("unable to update manifest: %s", gjson.GetBytes(respBody, "message").String())
	case http.StatusUnauthorized:
		return fmt.Errorf("unable to authorize user: %s", gjson.GetBytes(respBody, "message").String())
	default:
		response := gjson.GetBytes(respBody, "message").String()
		return fmt.Errorf("error connecting to server: %d %s: %s", resp.StatusCode, http.StatusText(resp.StatusCode), response)
	}

	return nil
}

func cliManifestUpdateAcknowledge(manifest []byte, host string, client *http.Client) error {
	url := url.URL{Scheme: "https", Host: host, Path: "update-manifest"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url.String(), bytes.NewReader(manifest))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Printf("Acknowledgement successful: %s\n", gjson.GetBytes(respBody, "data").String())
	case http.StatusNotFound:
		return fmt.Errorf("unable to update manifest: no pending update found: %s", gjson.GetBytes(respBody, "message").String())
	case http.StatusUnauthorized:
		return fmt.Errorf("unable to authorize user: %s", gjson.GetBytes(respBody, "message").String())
	default:
		response := gjson.GetBytes(respBody, "message").String()
		return fmt.Errorf("error connecting to server: %d %s: %s", resp.StatusCode, http.StatusText(resp.StatusCode), response)
	}

	return nil
}

func cliManifestUpdateCancel(host string, client *http.Client) error {
	url := url.URL{Scheme: "https", Host: host, Path: "update-cancel"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, url.String(), http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		fmt.Println("Cancellation successful")
	case http.StatusNotFound:
		return fmt.Errorf("unable to cancel manifest update: no pending update found: %s", gjson.GetBytes(respBody, "message").String())
	case http.StatusUnauthorized:
		return fmt.Errorf("unable to authorize user: %s", gjson.GetBytes(respBody, "message").String())
	default:
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf("error connecting to server: %d %s: %s", resp.StatusCode, http.StatusText(resp.StatusCode), response)
	}

	return nil
}

func cliManifestUpdateGet(output string, host string, client *http.Client) error {
	url := url.URL{Scheme: "https", Host: host, Path: "update-manifest"}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url.String(), http.NoBody)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	switch resp.StatusCode {
	case http.StatusOK:
		mnfB64 := gjson.GetBytes(respBody, "data.manifest").String()
		msg := gjson.GetBytes(respBody, "data.message")
		missingUsers := gjson.GetBytes(respBody, "data.missingUsers")

		mnfRaw, err := base64.StdEncoding.DecodeString(mnfB64)
		if err != nil {
			return err
		}
		var mnf map[string]interface{}
		if err := json.Unmarshal(mnfRaw, &mnf); err != nil {
			return err
		}
		removeNil(mnf)
		cleaned, err := json.Marshal(mnf)
		if err != nil {
			return err
		}

		consolidatedResponse := gjson.Parse(fmt.Sprintf(
			"{\n\"Manifest\": %s,\n\"Message\": \"%s\"\n\"MissingUsers\": %s\n}",
			string(cleaned),
			msg.String(),
			missingUsers.String(),
		)).Get(`@pretty:{"indent":"    "}`).String()

		if output == "" {
			fmt.Println(consolidatedResponse)
			return nil
		}

		return os.WriteFile(output, []byte(consolidatedResponse), 0o644)

	case http.StatusNotFound:
		return fmt.Errorf("no pending update found: %s", gjson.GetBytes(respBody, "message").String())
	default:
		response := gjson.GetBytes(respBody, "message")
		return fmt.Errorf("error connecting to server: %d %s: %s", resp.StatusCode, http.StatusText(resp.StatusCode), response)
	}
}
