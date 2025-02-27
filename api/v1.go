// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/edgelesssys/marblerun/api/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	apiv1 "github.com/edgelesssys/marblerun/coordinator/server/v1"
)

// getStatusV1 retrieves the status of the Coordinator using the legacy v1 API.
func getStatusV1(ctx context.Context, client *rest.Client) (int, string, error) {
	resp, err := client.Get(ctx, rest.StatusEndpoint, http.NoBody)
	if err != nil {
		return -1, "", err
	}

	var response apiv1.StatusResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return -1, "", fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return response.StatusCode, response.StatusMessage, nil
}

// manifestGetV1 retrieves the manifest of the Coordinator using the legacy v1 API.
func manifestGetV1(ctx context.Context, client *rest.Client) (mnf []byte, fingerprint string, signature []byte, err error) {
	resp, err := client.Get(ctx, rest.ManifestEndpoint, http.NoBody)
	if err != nil {
		return nil, "", nil, err
	}

	var response apiv1.ManifestSignatureResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, "", nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.Manifest, response.ManifestSignature, response.ManifestSignatureRootECDSA, nil
}

// manifestLogV1 retrieves the update log of the Coordinator using the legacy v1 API.
func manifestLogV1(ctx context.Context, client *rest.Client) ([]string, error) {
	resp, err := client.Get(ctx, rest.UpdateEndpoint, http.NoBody)
	if err != nil {
		return nil, err
	}
	return strings.Split(strings.TrimSpace(string(resp)), "\n"), nil
}

// manifestSetV1 sets the manifest of the Coordinator using the legacy v1 API.
func manifestSetV1(ctx context.Context, client *rest.Client, manifest []byte) (recoveryData map[string][]byte, err error) {
	resp, err := client.Post(ctx, rest.ManifestEndpoint, rest.ContentJSON, bytes.NewReader(manifest))
	if err != nil {
		return nil, err
	}

	if len(resp) > 0 {
		var response apiv1.RecoveryDataResponse
		if err := json.Unmarshal(resp, &response); err != nil {
			return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
		}
		recoveryData = response.RecoverySecrets
	}

	return recoveryData, nil
}

// manifestUpdateApplyV1 updates the Coordinator manifest using the legacy v1 API.
func manifestUpdateApplyV1(ctx context.Context, client *rest.Client, manifest []byte) error {
	_, err := client.Post(ctx, rest.UpdateEndpoint, rest.ContentJSON, bytes.NewReader(manifest))
	return err
}

// manifestUpdateAcknowledgeV1 acknowledges an update manifest using the legacy v1 API.
func manifestUpdateAcknowledgeV1(ctx context.Context, client *rest.Client, updateManifest []byte) (missingUsers []string, missingAcknowledgements int, err error) {
	resp, err := client.Post(ctx, rest.UpdateStatusEndpoint, rest.ContentJSON, bytes.NewReader(updateManifest))
	if err != nil {
		return nil, -1, err
	}

	missing, _, _ := strings.Cut(string(resp), " ")
	if missing == "All" {
		return nil, 0, nil
	}
	numMissing, err := strconv.Atoi(missing)
	if err != nil {
		return nil, -1, fmt.Errorf("parsing number of missing users: %w", err)
	}

	for i := 0; i < numMissing; i++ {
		missingUsers = append(missingUsers, fmt.Sprintf("User%d", i))
	}

	return missingUsers, numMissing, nil
}

// secretGetV1 requests secrets from the Coordinator using the legacy v1 API.
func secretGetV1(ctx context.Context, client *rest.Client, query []string) (map[string]manifest.Secret, error) {
	resp, err := client.Get(ctx, rest.SecretEndpoint, http.NoBody, query...)
	if err != nil {
		return nil, err
	}

	secretMap := make(map[string]manifest.Secret, len(query)/2)
	if err := json.Unmarshal(resp, &secretMap); err != nil {
		return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return secretMap, nil
}

// secretSetV1 sets secrets on the Coordinator using the legacy v1 API.
func secretSetV1(ctx context.Context, client *rest.Client, secrets map[string]manifest.UserSecret) error {
	secretDataJSON, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("marshalling secrets: %w", err)
	}
	_, err = client.Post(ctx, rest.SecretEndpoint, rest.ContentJSON, bytes.NewReader(secretDataJSON))
	return err
}
