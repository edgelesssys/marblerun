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

	"github.com/edgelesssys/marblerun/api/rest"
	"github.com/edgelesssys/marblerun/coordinator/manifest"
	apiv2 "github.com/edgelesssys/marblerun/coordinator/server/v2"
)

// recoverV2 performs recovery of the Coordinator using the v2 API.
func recoverV2(ctx context.Context, client *rest.Client, recoverySecret, recoverySecretSignature []byte) (remaining int, err error) {
	recoverySecretJSON, err := json.Marshal(apiv2.RecoveryRequest{
		RecoverySecret:          recoverySecret,
		RecoverySecretSignature: recoverySecretSignature,
	})
	if err != nil {
		return -1, fmt.Errorf("marshalling request: %w", err)
	}

	resp, err := client.Post(ctx, rest.V2API+rest.RecoverEndpoint, rest.ContentJSON, bytes.NewReader(recoverySecretJSON))
	if err != nil {
		return -1, err
	}

	var response apiv2.RecoveryResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return -1, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return response.Remaining, nil
}

// getStatusV2 retrieves the status of the Coordinator using the v2 API.
func getStatusV2(ctx context.Context, client *rest.Client) (int, string, error) {
	resp, err := client.Get(ctx, rest.V2API+rest.StatusEndpoint, http.NoBody)
	if err != nil {
		return -1, "", err
	}

	var response apiv2.StatusResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return -1, "", fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return response.Code, response.Message, nil
}

// manifestGetV2 retrieves the Coordinator manifest using the v2 API.
func manifestGetV2(ctx context.Context, client *rest.Client) (mnf []byte, fingerprint string, signature []byte, err error) {
	resp, err := client.Get(ctx, rest.V2API+rest.ManifestEndpoint, http.NoBody)
	if err != nil {
		return nil, "", nil, err
	}

	var response apiv2.ManifestGetResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, "", nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.Manifest, response.ManifestFingerprint, response.ManifestSignatureRootECDSA, nil
}

// manifestLogV2 retrieves the update log of the Coordinator using the v2 API.
func manifestLogV2(ctx context.Context, client *rest.Client) ([]string, error) {
	resp, err := client.Get(ctx, rest.V2API+rest.UpdateEndpoint, http.NoBody)
	if err != nil {
		return nil, err
	}

	var response apiv2.UpdateLogResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.UpdateLog, nil
}

// manifestSetV2 sets the Coordinator manifest using the v2 API.
func manifestSetV2(ctx context.Context, client *rest.Client, manifest []byte) (recoveryData map[string][]byte, err error) {
	request, err := json.Marshal(apiv2.ManifestSetRequest{Manifest: manifest})
	if err != nil {
		return nil, fmt.Errorf("marshalling request: %w", err)
	}

	resp, err := client.Post(ctx, rest.V2API+rest.ManifestEndpoint, rest.ContentJSON, bytes.NewReader(request))
	if err != nil {
		return nil, err
	}

	var response apiv2.ManifestSetResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return response.RecoverySecrets, nil
}

// manifestUpdateApplyV2 updates the Coordinator manifest using the v2 API.
func manifestUpdateApplyV2(ctx context.Context, client *rest.Client, manifest []byte) error {
	request, err := json.Marshal(apiv2.UpdateApplyRequest{Manifest: manifest})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	_, err = client.Post(ctx, rest.V2API+rest.UpdateEndpoint, rest.ContentJSON, bytes.NewReader(request))
	return err
}

// manifestUpdateAcknowledgeV2 acknowledges an update manifest using the v2 API.
func manifestUpdateAcknowledgeV2(ctx context.Context, client *rest.Client, updateManifest []byte) (missingUsers []string, missingAcknowledgments int, err error) {
	updateManifestJSON, err := json.Marshal(struct {
		Manifest []byte `json:"manifest"`
	}{
		Manifest: updateManifest,
	})
	if err != nil {
		return nil, -1, err
	}

	resp, err := client.Post(ctx, rest.V2API+rest.UpdateStatusEndpoint, rest.ContentJSON, bytes.NewReader(updateManifestJSON))
	if err != nil {
		return nil, -1, err
	}

	var response struct {
		Message                string   `json:"message"`
		MissingUsers           []string `json:"missingUsers"`
		MissingAcknowledgments int      `json:"missingAcknowledgments"`
	}
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, -1, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}

	return response.MissingUsers, response.MissingAcknowledgments, nil
}

// secretGetV2 requests secrets from the Coordinator using the v2 API.
func secretGetV2(ctx context.Context, client *rest.Client, query []string) (map[string]manifest.Secret, error) {
	resp, err := client.Get(ctx, rest.V2API+rest.SecretEndpoint, http.NoBody, query...)
	if err != nil {
		return nil, err
	}

	var response apiv2.SecretsGetResponse
	if err := json.Unmarshal(resp, &response); err != nil {
		return nil, fmt.Errorf("unmarshalling Coordinator response: %w", err)
	}
	return response.Secrets, nil
}

// secretSetV2 sets secrets on the Coordinator using the v2 API.
func secretSetV2(ctx context.Context, client *rest.Client, secrets map[string]manifest.UserSecret) error {
	request, err := json.Marshal(apiv2.SecretsSetRequest{Secrets: secrets})
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	_, err = client.Post(ctx, rest.V2API+rest.SecretEndpoint, rest.ContentJSON, bytes.NewReader(request))
	return err
}
