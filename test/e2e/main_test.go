//go:build e2e

/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: BUSL-1.1
*/

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	oss_mnf "github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/edgelesssys/marblerun/coordinator/state"
	"github.com/edgelesssys/marblerun/coordinator/store/stdstore"
	"github.com/edgelesssys/marblerun/test/e2e/cmd"
	"github.com/edgelesssys/marblerun/test/e2e/helm"
	"github.com/edgelesssys/marblerun/test/e2e/kubectl"
	"github.com/edgelesssys/marblerun/test/e2e/manifest"
	"github.com/edgelesssys/marblerun/util/k8sutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	localhost                          = "localhost"
	marbleClientPort                   = "8080"
	marbleClientPortInt                = 8080
	coordinatorClientPort              = "4433"
	coordinatorClientService           = "coordinator-client-api"
	coordinatorDeployment              = "marblerun-coordinator"
	coordinatorDeploymentSelectorLabel = "edgeless.systems/control-plane-component"
	coordinatorContainerName           = "coordinator"
	stateSecretName                    = "marblerun-state"
	kekMap                             = "marblerun-sealed-kek"
	manifestFile                       = "manifest.json"
	recoveryDataFile                   = "recoverydata.json"
	keyFileDefault                     = "key"
	publicKeyFileDefault               = "pub"
	certFileDefault                    = "crt"
	coordinatorCertFileDefault         = "coordinator.crt"

	defaultTimeout     = 30 * time.Minute
	eventuallyTimeout  = 5 * time.Minute
	eventuallyInterval = 5 * time.Second
)

var (
	replicas                     = flag.Int("replicas", 3, "number of Coordinator replicas to use for the test")
	cliPath                      = flag.String("cli", "", "path to MarbleRun CLI")
	kubeConfigPath               = flag.String("kubeconfig", "", "path to kubeconfig file")
	chartPath                    = flag.String("chart", "../../charts", "path to helm chart")
	accessToken                  = flag.String("access-token", "", "access token for the MarbleRun installation")
	coordinatorUpdateImageSuffix = flag.String("coordinator-update-image-suffix", "", "suffix of the coordinator image to use in update tests")
	marbleImageName              = flag.String("marble-image-name", "ghcr.io/edgelesssys/marblerun-e2e/test-marble", "name of the marble container image to use in tests")
	marbleImageVersion           = flag.String("marble-image-version", "latest", "version/tag of the marble container image to use in tests")
	eraConfigFile                = flag.String("era-config", "", "path to era config file, defaults to --insecure")
	marbleConfigFile             = flag.String("marble-config", "", "path to marble config file, if not given, an empty debug config is used")

	eraConfig    = "--insecure"
	marbleConfig = manifest.PackageProperties{
		Debug: true,
	}
)

func TestMain(m *testing.M) {
	flag.Parse()

	if *cliPath == "" || *kubeConfigPath == "" || *chartPath == "" || *accessToken == "" {
		flag.Usage()
		fmt.Fprintf(os.Stderr, "Required flags not set")
		os.Exit(1)
	}

	if *replicas < 1 {
		fmt.Fprintf(os.Stderr, "At least 1 replica is required to run the test")
		os.Exit(1)
	}

	if *eraConfigFile != "" {
		eraConfig = fmt.Sprintf("--era-config=%s", *eraConfigFile)
	}

	if *marbleConfigFile != "" {
		marbleConfigRaw, err := os.ReadFile(*marbleConfigFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read marble config file: %s", err)
			os.Exit(1)
		}
		if err := json.Unmarshal(marbleConfigRaw, &marbleConfig); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to unmarshal marble config: %s", err)
			os.Exit(1)
		}
	}

	os.Exit(m.Run())
}

func TestE2EActions(t *testing.T) {
	type testAction func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string)

	triggerRecoveryActions := []testAction{
		// Scale down Coordinators to 0
		func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace string, _ string) {
			t.Log("Scaling down Coordinator deployment to 0")
			require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
		},

		// Delete KEKs from namespace
		func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace, _ string) {
			t.Log("Deleting Key Encryption Keys")
			require.NoError(t, kubectl.DeleteConfigMap(ctx, namespace, kekMap))
		},

		// Scale back up and check for recovery mode
		func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
			t.Log("Scaling up Coordinator deployment to 1")
			require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 1))

			getStatus(ctx, t, kubectl, cmd, namespace, state.Recovery)
		},
	}

	recoverCoordinatorActions := []testAction{
		// Recover Coordinator
		func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
			recoverCoordinator(ctx, t, kubectl, cmd, manifest.DefaultUser, keyFileDefault, namespace, tmpDir)
		},

		// Verify recovered Coordinator has manifest set
		func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
			getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
		},

		// Scale instances back up
		func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace string, _ string) {
			t.Logf("Scaling up Coordinator deployment to %d", *replicas)
			require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))
		},

		// Verify all instances are accepting marbles
		func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
			getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
		},
	}

	verifyManifestHasntChangedAction := func(mnfFile string) func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
		return func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
			require := require.New(t)
			assert := assert.New(t)

			expectedMnf, err := os.ReadFile(filepath.Join(tmpDir, mnfFile))
			require.NoError(err)
			actualMnfFile := filepath.Join(tmpDir, "current.json")

			forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
				t.Logf("Checking manifest on %q", pod)
				if _, err := cmd.Run(
					ctx,
					"manifest", "get",
					net.JoinHostPort(localhost, port),
					"--output", actualMnfFile,
					eraConfig,
				); err != nil {
					return err
				}

				actualMnf, err := os.ReadFile(actualMnfFile)
				require.NoError(err)
				assert.Equal(expectedMnf, actualMnf)
				return nil
			})
		}
	}

	verifyMarblePodAction := func(marbleType string, checkFunc func(t *testing.T, res *http.Response, err error) error) testAction {
		return func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace, tmpDir string) {
			t.Logf("Starting Marble Pod %s in namespace %s", marbleType, namespace)
			podName, err := createMarblePod(ctx, kubectl, namespace, marbleType, nil, nil)
			require.NoError(t, err)

			coordinatorCertChain, err := os.ReadFile(filepath.Join(tmpDir, coordinatorCertFileDefault))
			require.NoError(t, err)
			caPool := x509.NewCertPool()
			require.True(t, caPool.AppendCertsFromPEM(coordinatorCertChain), "failed loading coordinator cert chain")
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{
						RootCAs: caPool,
					},
				},
			}

			t.Logf("Checking Marble Pod %s in namespace %s", marbleType, namespace)
			withPortForward(ctx, t, kubectl, namespace, podName, marbleClientPort, func(port string) error {
				req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://%s:%s", localhost, port), nil)
				if err != nil {
					return err
				}

				resp, err := client.Do(req)
				if resp != nil {
					defer resp.Body.Close()
				}
				return checkFunc(t, resp, err)
			})

			t.Logf("Deleting Marble Pod %s in namespace %s", marbleType, namespace)
			assert.NoError(t, kubectl.DeletePod(ctx, namespace, podName))
		}
	}

	testCases := map[string]struct {
		getStartingManifest func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest
		actions             []testAction
	}{
		"update single package multiple times": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				defaultPackage.SecurityVersion = 1
				return manifest.DefaultManifest(crt, key, defaultPackage)
			},
			actions: func() []testAction {
				defaultVersion := 1

				var actions []testAction

				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %d %s", res.StatusCode, res.Status)
					}
					return nil
				}))

				for i := 1; i < 5; i++ {
					idx := i
					actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
						require := require.New(t)
						assert := assert.New(t)

						// Create Update Manifest
						updateMnf := manifest.Manifest{
							Packages: map[string]manifest.PackageProperties{
								manifest.DefaultPackage: {
									SecurityVersion: uint(defaultVersion + idx),
								},
							},
						}
						updateMnfRaw, err := json.MarshalIndent(updateMnf, "", "  ")
						require.NoError(err)
						t.Logf("Setting update manifest:\n%s", updateMnfRaw)
						updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, updateMnfRaw, certFileDefault, keyFileDefault)

						// Verify status of all MarbleRun instances
						getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

						// Verify package was updated for all instances
						t.Log("Verifying package update")
						forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
							if _, err := cmd.Run(
								ctx,
								"manifest", "log",
								net.JoinHostPort(localhost, port),
								"--output", filepath.Join(tmpDir, "log.json"),
								"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
								eraConfig,
							); err != nil {
								return err
							}

							log, err := os.ReadFile(filepath.Join(tmpDir, "log.json"))
							require.NoError(err)

							t.Logf("Update log:\n%s", log)
							logEntries, err := parseUpdateLog(log)
							require.NoError(err)

							require.Len(logEntries, 1+idx) // 1+i log entries expected: i for the updates, 1 for the initial manifest set

							assert.Equal(manifest.DefaultPackage, logEntries[idx].Package)
							assert.Equal(uint(defaultVersion+idx), logEntries[idx].NewVersion)
							assert.Equal(manifest.DefaultUser, logEntries[idx].User)
							return nil
						})
					})

					verifyResponse := func(t *testing.T, res *http.Response, err error) error {
						wantErr := i+defaultVersion > int(marbleConfig.SecurityVersion)
						if wantErr {
							assert.Error(t, err)
							return nil // return early, we don't want to retry if this call succeeds unexpectedly
						}

						if err != nil {
							return err
						}
						if http.StatusOK != res.StatusCode {
							return fmt.Errorf("http.Get returned: %s", res.Status)
						}
						return nil
					}
					actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyResponse))
				}

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)
					// Try to downgrade security version back to the initial version
					updateMnf := manifest.Manifest{
						Packages: map[string]manifest.PackageProperties{
							manifest.DefaultPackage: {
								SecurityVersion: uint(defaultVersion),
							},
						},
					}
					updateMnfRaw, err := json.MarshalIndent(updateMnf, "", "  ")
					require.NoError(err)
					t.Logf("Trying to downgrade version using update manifest:\n%s", updateMnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, updateMnfRaw, 0o644))

					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						if err == nil {
							return errors.New("expected error, got none")
						}

						if !strings.Contains(err.Error(), "update manifest tries to downgrade SecurityVersion of the original manifest") {
							return fmt.Errorf("expected error to contain 'tries to downgrade SecurityVersion', got %q", err)
						}
						return nil
					})
				})

				return actions
			}(),
		},
		"user uploaded secret remains after update": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				defaultPackage.SecurityVersion-- // decrease security version to allow for updates
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				marble := mnf.Marbles[manifest.DefaultMarble]
				marbleSecretFile := "/test-secret"
				marble.Parameters.Argv = []string{"marble", "secrets", marbleSecretFile}
				marble.Parameters.Files[marbleSecretFile] = oss_mnf.File{
					Data:     "{{ raw .Secrets.UserDefinedKey }}",
					Encoding: "string",
				}
				mnf.Marbles[manifest.DefaultMarble] = marble

				mnf.Secrets["UserDefinedKey"] = manifest.Secret{
					Type:        oss_mnf.SecretTypeSymmetricKey,
					Size:        128,
					UserDefined: true,
				}
				secRole := mnf.Roles[manifest.DefaultAccessUserDataRole]
				secRole.ResourceNames = append(secRole.ResourceNames, "UserDefinedKey")
				mnf.Roles[manifest.DefaultAccessUserDataRole] = secRole
				return mnf
			},
			actions: func() []testAction {
				marbleSecretFile := "/test-secret"
				keyName := "UserDefinedKey"
				userDefinedSecrets := map[string]oss_mnf.UserSecret{
					keyName: {
						Key: bytes.Repeat([]byte{0x01}, 128/8),
					},
				}

				var actions []testAction

				verifySecret := func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					readAndVerifySecret(ctx, t, kubectl, cmd, keyName, namespace, tmpDir, userDefinedSecrets[keyName].Key)
				}

				// Pod should not start yet, since the secret isn't set
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(t *testing.T, _ *http.Response, err error) error {
					assert.Error(t, err)
					return nil
				}))

				// Upload user defined key
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					secretsJSON, err := json.MarshalIndent(userDefinedSecrets, "", "  ")
					require.NoError(err)
					secretPath := filepath.Join(tmpDir, "secrets.json")
					require.NoError(os.WriteFile(secretPath, secretsJSON, 0o644))

					t.Logf("Uploading user defined secret: %s", secretsJSON)
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"secret", "set",
							secretPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						return err
					})
				})

				verifySecretInPod := func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					body, err := io.ReadAll(res.Body)
					if err != nil {
						return err
					}
					marbleSecrets := make(map[string][]byte)
					if err := json.Unmarshal(body, &marbleSecrets); err != nil {
						return fmt.Errorf("failed to unmarshal response '%s': %w", body, err)
					}
					if len(marbleSecrets) != 1 {
						return fmt.Errorf("expected one secret from Marble, got %d", len(marbleSecrets))
					}
					if !bytes.Equal(userDefinedSecrets[keyName].Key, marbleSecrets[marbleSecretFile]) {
						return fmt.Errorf("expected secret from body '%s' to be %v, got %v", body, userDefinedSecrets[keyName].Key, marbleSecrets[marbleSecretFile])
					}
					return nil
				}

				// The secret should now be set and the Marble can start
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifySecretInPod))

				// Update package
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					updateMnf := manifest.Manifest{
						Packages: map[string]manifest.PackageProperties{
							manifest.DefaultPackage: {
								// The test sets up the initial manifest with a security version lower than the actual version
								// Update to current security version
								SecurityVersion: marbleConfig.SecurityVersion,
							},
						},
					}
					updateMnfRaw, err := json.MarshalIndent(updateMnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", updateMnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, updateMnfRaw, certFileDefault, keyFileDefault)
				})

				// Verify secrets
				actions = append(actions, verifySecret)

				// The same secret should still be set for the Marble
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifySecretInPod))

				// Update complete manifest
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					var mnf manifest.Manifest
					mnfRaw, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
					require.NoError(err)
					require.NoError(json.Unmarshal(mnfRaw, &mnf))

					// Add a new Secret to the manifest
					mnf.Secrets["SomeCertificate"] = manifest.Secret{
						Type: oss_mnf.SecretTypeCertRSA,
						Size: 2048,
					}

					mnfRaw, err = json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Verify secrets again
				actions = append(actions, verifySecret)

				// The same secret should also be set for the Marble
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifySecretInPod))

				return actions
			}(),
		},
		"secrets can be removed by updates": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)

				mnf.Secrets["SharedKey"] = manifest.Secret{
					Type:   oss_mnf.SecretTypeSymmetricKey,
					Size:   128,
					Shared: true,
				}
				mnf.Roles["ReadSecret"] = oss_mnf.Role{
					ResourceType:  "Secrets",
					ResourceNames: []string{"SharedKey"},
					Actions:       []string{"ReadSecret"},
				}
				defaultUser := mnf.Users[manifest.DefaultUser]
				defaultUser.Roles = append(defaultUser.Roles, "ReadSecret")
				mnf.Users[manifest.DefaultUser] = defaultUser

				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					_, err := readSecret(ctx, t, kubectl, cmd, "SharedKey", namespace, tmpDir, false)
					assert.NoError(t, err)
				})
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					_, err := readSecret(ctx, t, kubectl, cmd, manifest.DefaultUserSecret, namespace, tmpDir, false)
					assert.NoError(t, err) // Empty secret
				})

				// Set secret
				userDefinedSecrets := map[string]oss_mnf.UserSecret{
					manifest.DefaultUserSecret: {
						Key: []byte("secret"),
					},
				}
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					secretsJSON, err := json.MarshalIndent(userDefinedSecrets, "", "  ")
					require.NoError(err)
					secretPath := filepath.Join(tmpDir, "secrets.json")
					require.NoError(os.WriteFile(secretPath, secretsJSON, 0o644))

					t.Logf("Uploading user defined secret: %s", secretsJSON)
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"secret", "set",
							secretPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						return err
					})
				})

				// Secret is now set
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					readAndVerifySecret(ctx, t, kubectl, cmd, manifest.DefaultUserSecret, namespace, tmpDir, userDefinedSecrets[manifest.DefaultUserSecret].Key)
				})

				// Apply an update manifest that removes the secrets
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					var mnf manifest.Manifest
					mnfRaw, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
					require.NoError(err)
					require.NoError(json.Unmarshal(mnfRaw, &mnf))
					delete(mnf.Secrets, "SharedKey")
					delete(mnf.Secrets, manifest.DefaultUserSecret)

					// Remove roles referencing deleted secrets
					// Otherwise the update will fail
					delete(mnf.Roles, "ReadSecret")
					delete(mnf.Roles, manifest.DefaultAccessUserDataRole)
					defaultUser := mnf.Users[manifest.DefaultUser]
					defaultUser.Roles = []string{manifest.DefaultUpdateManifestRole, manifest.DefaultUpdatePackageRole}
					mnf.Users[manifest.DefaultUser] = defaultUser

					mnfRaw, err = json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Secret is now removed
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					_, err := readSecret(ctx, t, kubectl, cmd, manifest.DefaultUserSecret, namespace, tmpDir, true)
					assert.Error(t, err, "Secret should not be set")
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					_, err := readSecret(ctx, t, kubectl, cmd, "ProtectedFilesKey", namespace, tmpDir, true)
					assert.Error(t, err, "Secret should not be set")
				})

				return actions
			}(),
		},
		"chained manifest updates": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				_, user2Key := manifest.GenerateKey(t)
				user2Cert := manifest.GenerateCertificate(t, user2Key)
				user2KeyName := filepath.Join("user2", keyFileDefault)
				user2CertName := filepath.Join("user2", certFileDefault)

				var actions []testAction

				// Write second user's key and cert to tmpDir
				actions = append(actions, func(_ context.Context, t *testing.T, _ *kubectl.Kubectl, _ *cmd.Cmd, _, tmpDir string) {
					require := require.New(t)

					// Write user2 key and cert
					require.NoError(os.MkdirAll(filepath.Join(tmpDir, "user2"), 0o755))
					privEncoded, err := x509.MarshalPKCS8PrivateKey(user2Key)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user2KeyName), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user2CertName), user2Cert, 0o644))
				})

				// Update manifest to add a new user
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.Users["user2"] = oss_mnf.User{
						Certificate: string(user2Cert),
						Roles:       []string{manifest.DefaultUpdateManifestRole, manifest.DefaultUpdatePackageRole},
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Single user in original manifest, there should be no pending update
				actions = append(actions, verifyNoPendingUpdates)

				// Apply update to add a new package
				// The update command is issued by the default user and has to be acknowledged by user2
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["package2"] = manifest.PackageProperties{
						UniqueID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)

					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault) // Update is now pending
				})

				// Verify update is pending
				actions = append(actions, verifyPendingUpdates(manifestFile))

				// Acknowledge update as user2
				// This will apply the update
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					updateAcknowledge(ctx, t, kubectl, cmd, namespace, tmpDir, manifestFile, user2CertName, user2KeyName, 0)
				})

				// Update applied, there should be no pending updates
				actions = append(actions, verifyNoPendingUpdates)

				// Apply update to remove default user
				// The update command is issued by the default user
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					delete(mnf.Users, manifest.DefaultUser)

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault) // Update is now pending
				})

				actions = append(actions, verifyPendingUpdates(manifestFile))

				// Acknowledge update as user2
				// This will apply the update
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					updateAcknowledge(ctx, t, kubectl, cmd, namespace, tmpDir, manifestFile, user2CertName, user2KeyName, 0)
				})

				// Update applied, there should be no pending updates
				actions = append(actions, verifyNoPendingUpdates)

				return actions
			}(),
		},
		"two groups of users with update permissions": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				_, user2Key := manifest.GenerateKey(t)
				user2Cert := manifest.GenerateCertificate(t, user2Key)
				user2KeyName := filepath.Join("user2", keyFileDefault)
				user2CertName := filepath.Join("user2", certFileDefault)

				_, user3Key := manifest.GenerateKey(t)
				user3Cert := manifest.GenerateCertificate(t, user3Key)
				user3KeyName := filepath.Join("user3", keyFileDefault)
				user3CertName := filepath.Join("user3", certFileDefault)

				var actions []testAction

				// Write second and third user's key and cert to tmpDir
				actions = append(actions, func(_ context.Context, t *testing.T, _ *kubectl.Kubectl, _ *cmd.Cmd, _, tmpDir string) {
					require := require.New(t)

					// Write user key and cert
					require.NoError(os.MkdirAll(filepath.Join(tmpDir, "user2"), 0o755))
					privEncoded, err := x509.MarshalPKCS8PrivateKey(user2Key)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user2KeyName), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user2CertName), user2Cert, 0o644))

					require.NoError(os.MkdirAll(filepath.Join(tmpDir, "user3"), 0o755))
					privEncoded, err = x509.MarshalPKCS8PrivateKey(user3Key)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user3KeyName), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user3CertName), user3Cert, 0o644))
				})

				// Update manifest to add new users and a new group for them
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnfRaw, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
					require.NoError(err)
					var mnf manifest.Manifest
					require.NoError(json.Unmarshal(mnfRaw, &mnf))

					mnf.Roles["AlsoUpdateManifest"] = oss_mnf.Role{
						ResourceType: "Manifest",
						Actions:      []string{"UpdateManifest"},
					}

					mnf.Users["user2"] = oss_mnf.User{
						Certificate: string(user2Cert),
						Roles:       []string{"AlsoUpdateManifest", manifest.DefaultUpdatePackageRole},
					}
					mnf.Users["user3"] = oss_mnf.User{
						Certificate: string(user3Cert),
						Roles:       []string{"AlsoUpdateManifest", manifest.DefaultUpdatePackageRole},
					}

					mnfRaw, err = json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// There should be no pending updates
				actions = append(actions, verifyNoPendingUpdates)

				// Apply update to increase security version of a package
				// This shouldn't require any extra acknowledgements
				for idx, user := range []struct{ certFile, keyFile string }{
					{certFile: certFileDefault, keyFile: keyFileDefault},
					{certFile: user2CertName, keyFile: user2KeyName},
					{certFile: user3CertName, keyFile: user3KeyName},
				} {
					actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
						require := require.New(t)

						defaultMnf := manifest.DefaultManifest(nil, nil, marbleConfig)
						// Create Update Manifest
						mnf := manifest.Manifest{
							Packages: map[string]manifest.PackageProperties{
								manifest.DefaultPackage: {
									SecurityVersion: defaultMnf.Packages[manifest.DefaultPackage].SecurityVersion + uint(idx+1),
								},
							},
						}

						mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
						require.NoError(err)
						t.Logf("Setting update manifest:\n%s", mnfRaw)
						updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, user.certFile, user.keyFile)
					})

					// No pending updates
					actions = append(actions, verifyNoPendingUpdates)
				}

				// Add a new package as the default user
				// This should require an acknowledgement from user2 and user3
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Applying manifest update as default user")
					require := require.New(t)

					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["package2"] = manifest.PackageProperties{
						UniqueID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// There should be a pending update
				actions = append(actions, verifyPendingUpdates("update.json"))

				// Acknowledge the update as user2
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Acknowledging update as user2")
					updateAcknowledge(ctx, t, kubectl, cmd, namespace, tmpDir, "update.json", user2CertName, user2KeyName, 1)
				})

				// And as user3
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Acknowledging update as user3")
					updateAcknowledge(ctx, t, kubectl, cmd, namespace, tmpDir, "update.json", user3CertName, user3KeyName, 0)
				})

				// No pending updates
				actions = append(actions, verifyNoPendingUpdates)

				return actions
			}(),
		},
		"recover state": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifyManifestHasntChangedAction(manifestFile))

				// Run all test actions again to verify the recovered Coordinator behaves the same
				actions = append(actions, actions...)

				return actions
			}(),
		},
		"recover state ephemeral encryption": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, triggerRecoveryActions...)

				recoveryDir := "recovery"
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require.NoError(t, os.RemoveAll(filepath.Join(tmpDir, recoveryDir)))
					require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, recoveryDir), 0o755))
				})

				// Extract recovery secret
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)
					recoveryJSON, err := os.ReadFile(filepath.Join(tmpDir, recoveryDataFile))
					require.NoError(err)

					t.Logf("Parsing recovery data from %s", recoveryJSON)
					encryptedRecoveryKeyFile := filepath.Join(tmpDir, "encrypted_recovery_key")
					encryptedRecoveryData := map[string]map[string][]byte{}
					require.NoError(json.Unmarshal(recoveryJSON, &encryptedRecoveryData))
					keyMap := encryptedRecoveryData["RecoverySecrets"]
					require.NoError(os.WriteFile(encryptedRecoveryKeyFile, keyMap[manifest.DefaultUser], 0o644))
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Logf("Retrieving ephemeral encryption key from the Coordinator")
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(ctx,
							"recover-with-signature", "public-key", net.JoinHostPort(localhost, port),
							"--output", filepath.Join(tmpDir, recoveryDir, "coordinator_public_key.pem"),
							eraConfig,
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Logf("Signing recovery secret with private key")
					_, err := cmd.Run(ctx,
						"recover-with-signature", "sign-secret",
						filepath.Join(tmpDir, "encrypted_recovery_key"),
						"--output", filepath.Join(tmpDir, recoveryDir, "recovery_secret.sig"),
						"--key", filepath.Join(tmpDir, keyFileDefault),
					)
					require.NoError(t, err)
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Logf("Encrypting recovery secret with Coordinator public key")
					_, err := cmd.Run(ctx,
						"recover-with-signature", "encrypt-secret",
						filepath.Join(tmpDir, "encrypted_recovery_key"),
						"--key", filepath.Join(tmpDir, keyFileDefault),
						"--coordinator-pub-key", filepath.Join(tmpDir, recoveryDir, "coordinator_public_key.pem"),
						"--output", filepath.Join(tmpDir, recoveryDir, "recovery_secret.enc"),
					)
					require.NoError(t, err)
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Logf("Recovering Coordinator")
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(ctx,
							"recover-with-signature",
							filepath.Join(tmpDir, recoveryDir, "recovery_secret.enc"), net.JoinHostPort(localhost, port),
							"--signature", filepath.Join(tmpDir, recoveryDir, "recovery_secret.sig"),
							eraConfig,
						)
						return err
					})
				})

				// Verify recovered Coordinator has manifest set
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				// Scale instances back up
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace string, _ string) {
					t.Logf("Scaling up Coordinator deployment to %d", *replicas)
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))
				})

				// Verify all instances are accepting marbles
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				// Run all test actions again to verify the recovered Coordinator behaves the same
				actions = append(actions, actions...)

				return actions
			}(),
		},
		"recover state multiparty": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				mnf.RecoveryKeys[manifest.DefaultUser2] = mnf.RecoveryKeys[manifest.DefaultUser]
				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				verifyMarbleHasStarted := func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					return nil
				}

				// Before recovery, a Marble should start without Problems
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleHasStarted))

				actions = append(actions, triggerRecoveryActions...)

				// While in recovery mode, the Coordinator should reject new Marbles
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(t *testing.T, _ *http.Response, err error) error {
					assert.Error(t, err)
					return nil
				}))

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					recoverCoordinator(ctx, t, kubectl, cmd, manifest.DefaultUser2, keyFileDefault, namespace, tmpDir)
				})
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifyManifestHasntChangedAction(manifestFile))

				// After recovery, Marbles should start again
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleHasStarted))

				// Run all test actions again to verify the recovered Coordinator behaves the same
				actions = append(actions, actions...)

				return actions
			}(),
		},
		"recover state shamir": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				mnf.RecoveryKeys[manifest.DefaultUser2] = mnf.RecoveryKeys[manifest.DefaultUser]
				mnf.RecoveryKeys["shamir"] = mnf.RecoveryKeys[manifest.DefaultUser]
				mnf.Config.RecoveryThreshold = 2
				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				verifyMarbleHasStarted := func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					return nil
				}

				// Before recovery, a Marble should start without Problems
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleHasStarted))

				actions = append(actions, triggerRecoveryActions...)

				// While in recovery mode, the Coordinator should reject new Marbles
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(t *testing.T, _ *http.Response, err error) error {
					assert.Error(t, err)
					return nil
				}))

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					recoverCoordinator(ctx, t, kubectl, cmd, manifest.DefaultUser2, keyFileDefault, namespace, tmpDir)
				})
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifyManifestHasntChangedAction(manifestFile))

				// After recovery, Marbles should start again
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleHasStarted))

				// Run all test actions again to verify the recovered Coordinator behaves the same
				actions = append(actions, actions...)

				return actions
			}(),
		},
		"recover state multiparty without recovery data": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				mnf.RecoveryKeys[manifest.DefaultUser2] = mnf.RecoveryKeys[manifest.DefaultUser]
				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				verifyMarbleHasStarted := func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					return nil
				}
				// Before recovery, a Marble should start without Problems
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleHasStarted))

				// Remove recovery data from state secret
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace string, _ string) {
					secretData, err := kubectl.GetSecretData(ctx, namespace, stateSecretName)
					require.NoError(t, err)
					sealedData := secretData[stdstore.SealedDataFname]
					recoveryDataLen := binary.LittleEndian.Uint32(sealedData[:4])
					require.EqualValues(t, 145, recoveryDataLen) // len(`{"...64chars...":true,"...64chars...":true}`)
					secretData[stdstore.SealedDataFname] = append(make([]byte, 4), sealedData[4+recoveryDataLen:]...)
					require.NoError(t, kubectl.UpdateSecret(ctx, namespace, stateSecretName, secretData))
				})

				actions = append(actions, triggerRecoveryActions...)

				// While in recovery mode, the Coordinator should reject new Marbles
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(t *testing.T, _ *http.Response, err error) error {
					assert.Error(t, err)
					return nil
				}))

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					recoverCoordinator(ctx, t, kubectl, cmd, manifest.DefaultUser2, keyFileDefault, namespace, tmpDir)
				})
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifyManifestHasntChangedAction(manifestFile))

				// After recovery, Marbles should start again
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleHasStarted))

				// Recover again to verify that it works with the recreated recovery data
				actions = append(actions, actions[1:]...)

				return actions
			}(),
		},
		"recover secrets": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				marble := mnf.Marbles[manifest.DefaultMarble]
				marbleSecretFile := "/test-secret"
				marble.Parameters.Argv = []string{"marble", "secrets", marbleSecretFile}
				marble.Parameters.Files[marbleSecretFile] = oss_mnf.File{
					Data:     fmt.Sprintf("{{ raw .Secrets.%s }}", manifest.DefaultUserSecret),
					Encoding: "string",
				}
				mnf.Marbles[manifest.DefaultMarble] = marble
				return mnf
			},
			actions: func() []testAction {
				marbleSecretFile := "/test-secret"
				keyName := manifest.DefaultUserSecret
				userDefinedSecrets := map[string]oss_mnf.UserSecret{
					keyName: {Key: []byte("custom secret")},
				}

				verifySecret := func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					readAndVerifySecret(ctx, t, kubectl, cmd, keyName, namespace, tmpDir, userDefinedSecrets[keyName].Key)
				}

				var actions []testAction

				// Marble can't start before secret is set
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(t *testing.T, _ *http.Response, err error) error {
					assert.Error(t, err)
					return nil
				}))

				// Upload user defined secret
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					setSecret(ctx, t, kubectl, cmd, namespace, tmpDir, certFileDefault, keyFileDefault, userDefinedSecrets)
				})

				// Verify the secret is set
				actions = append(actions, verifySecret)

				// Verify the Marble can access the secrets
				verifyMarbleSecret := func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					body, err := io.ReadAll(res.Body)
					if err != nil {
						return err
					}
					marbleSecrets := make(map[string][]byte)
					if err := json.Unmarshal(body, &marbleSecrets); err != nil {
						return fmt.Errorf("failed to unmarshal response '%s': %w", body, err)
					}
					if len(marbleSecrets) != 1 {
						return fmt.Errorf("expected one secret from Marble, got %d", len(marbleSecrets))
					}
					if !bytes.Equal(userDefinedSecrets[keyName].Key, marbleSecrets[marbleSecretFile]) {
						return fmt.Errorf("expected secret from body '%s' to be %v, got %v", body, userDefinedSecrets[keyName].Key, marbleSecrets[marbleSecretFile])
					}
					return nil
				}
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleSecret))

				// Trigger recovery
				actions = append(actions, triggerRecoveryActions...)

				// Recover Coordinator
				actions = append(actions, recoverCoordinatorActions...)

				// Verify the secret is still set
				actions = append(actions, verifySecret)

				// Verify the Marble can still access the secrets
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleSecret))

				// Recover again to verify the recovered Coordinator behaves the same
				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifySecret)
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, verifyMarbleSecret))

				return actions
			}(),
		},
		"overwrite recovery": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				newMnfFile := "manifest_2.json"
				var actions []testAction

				// Trigger recovery
				actions = append(actions, triggerRecoveryActions...)

				// Overwrite recovery state with a new manifest
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)

					// Create new Manifest
					pub, priv := manifest.GenerateKey(t)
					crt := manifest.GenerateCertificate(t, priv)
					newMnf := manifest.DefaultManifest(crt, pub, marbleConfig)

					mnfRaw, err := json.MarshalIndent(newMnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, newMnfFile), mnfRaw, 0o644))
					t.Logf("Setting new manifest:\n%s", mnfRaw)

					// Overwrite recovery state
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "set",
							filepath.Join(tmpDir, newMnfFile), net.JoinHostPort(localhost, port),
							"--recoverydata", filepath.Join(tmpDir, recoveryDataFile),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						return err
					})
					t.Log("New Manifest set")
				})

				// Verify all instances are accepting marbles
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				// Verify the new manifest is set on all instances
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)
					assert := assert.New(t)

					expectedMnf, err := os.ReadFile(filepath.Join(tmpDir, newMnfFile))
					require.NoError(err)
					actualMnfFile := filepath.Join(tmpDir, "current.json")

					forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
						t.Logf("Checking manifest on %q", pod)
						if _, err := cmd.Run(
							ctx,
							"manifest", "get",
							net.JoinHostPort(localhost, port),
							"--output", actualMnfFile,
							eraConfig,
						); err != nil {
							return err
						}

						actualMnf, err := os.ReadFile(actualMnfFile)
						require.NoError(err)
						assert.Equal(expectedMnf, actualMnf)
						return nil
					})
				})

				// Since a new manifest was set, the original user should no longer be able to update the manifest
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnf := manifest.Manifest{
						Packages: map[string]manifest.PackageProperties{
							manifest.DefaultPackage: {SecurityVersion: 999},
						},
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					// Update should fail
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						if !strings.Contains(err.Error(), "unauthorized user") {
							return fmt.Errorf("expected error to contain 'unauthorized user', got %q", err)
						}
						return nil
					})
				})

				return actions
			}(),
		},
		"recover update": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				// Marble should start without Problems
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					return nil
				}))

				// Update manifest to add a new package and Marble
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["package2"] = marbleConfig
					newMarble := mnf.Marbles[manifest.DefaultMarble]
					newMarble.Package = "package2"
					mnf.Marbles["marble2"] = newMarble

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Update SecurityVersion of package1
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnf := manifest.Manifest{
						Packages: map[string]manifest.PackageProperties{
							manifest.DefaultPackage: {SecurityVersion: 999},
						},
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// The default Marble should now be unable to start since the SecurityVersion was increased
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(t *testing.T, _ *http.Response, err error) error {
					assert.Error(t, err)
					return nil
				}))

				// marble2, which we just added can start without problems
				actions = append(actions, verifyMarblePodAction("marble2", func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					return nil
				}))

				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, recoverCoordinatorActions...)

				// Verify the recovered Coordinator has the new manifest applied
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)
					assert := assert.New(t)

					expectedMnf, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
					require.NoError(err)
					actualMnfFile := filepath.Join(tmpDir, "current.json")

					forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
						t.Logf("Checking manifest on %q", pod)
						if _, err := cmd.Run(
							ctx,
							"manifest", "get",
							net.JoinHostPort(localhost, port),
							"--output", actualMnfFile,
							eraConfig,
						); err != nil {
							return err
						}

						actualMnf, err := os.ReadFile(actualMnfFile)
						require.NoError(err)
						assert.Equal(expectedMnf, actualMnf)
						return nil
					})
				})

				// Verify the package update was applied
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)
					assert := assert.New(t)
					forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
						if _, err := cmd.Run(
							ctx,
							"manifest", "log",
							net.JoinHostPort(localhost, port),
							"--output", filepath.Join(tmpDir, "log.json"),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						); err != nil {
							return err
						}

						log, err := os.ReadFile(filepath.Join(tmpDir, "log.json"))
						require.NoError(err)

						t.Logf("Update log:\n%s", log)
						logEntries, err := parseUpdateLog(log)
						require.NoError(err)

						// 4 log entries expected:
						//  1 for the initial manifest set
						//  2 for the manifest update (1 about initiating the update, 1 about completing it)
						//  1 for the package update
						require.Len(logEntries, 4)

						assert.Equal(manifest.DefaultPackage, logEntries[3].Package)
						assert.Equal(uint(999), logEntries[3].NewVersion)
						assert.Equal(manifest.DefaultUser, logEntries[3].User)
						return nil
					})
				})

				// Verify the default Marble is still not allowed to start
				actions = append(actions, verifyMarblePodAction(manifest.DefaultMarble, func(t *testing.T, _ *http.Response, err error) error {
					assert.Error(t, err)
					return nil
				}))

				// Verify marble2 can still start
				actions = append(actions, verifyMarblePodAction("marble2", func(_ *testing.T, res *http.Response, err error) error {
					if err != nil {
						return err
					}
					if http.StatusOK != res.StatusCode {
						return fmt.Errorf("http.Get returned: %s", res.Status)
					}
					return nil
				}))

				return actions
			}(),
		},
		"recover pending update": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)

				// Add a second user with update permissions to enable multi party updates
				_, priv := manifest.GenerateKey(t)
				user2Cert := manifest.GenerateCertificate(t, priv)
				mnf.Users["user2"] = oss_mnf.User{
					Certificate: string(user2Cert),
					Roles:       []string{manifest.DefaultUpdateManifestRole, manifest.DefaultUpdatePackageRole},
				}
				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				// Start a manifest update to add a new package
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)

					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["package2"] = manifest.PackageProperties{
						UniqueID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Verify the update is pending
				actions = append(actions, verifyPendingUpdates("update.json"))

				// Trigger recovery
				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, recoverCoordinatorActions...)

				// Verify the update is still pending
				actions = append(actions, verifyPendingUpdates("update.json"))

				return actions
			}(),
		},
		"secret lifecycle": {
			getStartingManifest: func(cert, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(cert, key, defaultPackage)
				mnf.Secrets["UserKey"] = manifest.Secret{
					Type:        oss_mnf.SecretTypeSymmetricKey,
					Size:        128,
					UserDefined: true,
				}
				secretRole := mnf.Roles[manifest.DefaultAccessUserDataRole]
				secretRole.ResourceNames = append(secretRole.ResourceNames, "UserKey")
				mnf.Roles[manifest.DefaultAccessUserDataRole] = secretRole

				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				symmetricKeyName := "UserKey"
				plainSecretName := manifest.DefaultUserSecret
				symmetricKey := bytes.Repeat([]byte{0x01}, 128/8)

				plainSecret := []byte("custom secret")

				verifySecret := func(keyName string, expected []byte) func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					return func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
						readAndVerifySecret(ctx, t, kubectl, cmd, keyName, namespace, tmpDir, expected)
					}
				}

				// Upload secrets
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					newSecrets := map[string]oss_mnf.UserSecret{
						symmetricKeyName: {Key: symmetricKey},
						plainSecretName:  {Key: plainSecret},
					}
					setSecret(ctx, t, kubectl, cmd, namespace, tmpDir, certFileDefault, keyFileDefault, newSecrets)
				})

				// Verify symmetric key is set
				actions = append(actions, verifySecret(symmetricKeyName, symmetricKey))

				// Verify plain secret is set
				actions = append(actions, verifySecret(plainSecretName, plainSecret))

				// Check that we can update the secrets
				newSymmetricKey := bytes.Repeat([]byte{0x02}, 128/8)
				newPlainSecret := []byte("new secret")
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					newSecrets := map[string]oss_mnf.UserSecret{
						symmetricKeyName: {Key: newSymmetricKey},
						plainSecretName:  {Key: newPlainSecret},
					}

					setSecret(ctx, t, kubectl, cmd, namespace, tmpDir, certFileDefault, keyFileDefault, newSecrets)
				})

				// Verify symmetric key is updated
				actions = append(actions, verifySecret(symmetricKeyName, newSymmetricKey))

				// Verify plain secret is updated
				actions = append(actions, verifySecret(plainSecretName, newPlainSecret))

				// Check that we can not set a secret with an invalid size
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)
					newSecrets := map[string]oss_mnf.UserSecret{
						symmetricKeyName: {
							Key: bytes.Repeat([]byte{0x02}, 25),
						},
					}

					secretsJSON, err := json.MarshalIndent(newSecrets, "", "  ")
					require.NoError(err)
					secretPath := filepath.Join(tmpDir, "secrets.json")
					require.NoError(os.WriteFile(secretPath, secretsJSON, 0o644))

					t.Logf("Uploading invalid user defined secret: %s", secretsJSON)
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err = cmd.Run(
							ctx,
							"secret", "set",
							secretPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						if !strings.Contains(err.Error(), "declared size and actual size don't match") {
							return fmt.Errorf("expected error to contain 'declared size and actual size don't match', got %q", err)
						}
						return nil
					})
				})

				return actions
			}(),
		},
		"coordinator image update": {
			getStartingManifest: manifest.DefaultManifest,
			actions: []testAction{
				func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, _ string) {
					require := require.New(t)
					image, err := kubectl.GetDeploymentImage(ctx, namespace, coordinatorDeployment, coordinatorContainerName)
					require.NoError(err)
					image = getCoordinatorUpdateImage(t, image)
					require.NoError(kubectl.SetDeploymentImage(ctx, namespace, coordinatorDeployment, coordinatorContainerName, image))
					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				},
			},
		},
		"reject unauthorized user": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, func(_ context.Context, t *testing.T, _ *kubectl.Kubectl, _ *cmd.Cmd, _, tmpDir string) {
					t.Log("Generating unauthorized credentials for test")
					require := require.New(t)

					unauthorizedDir := filepath.Join(tmpDir, "unauthorized")
					require.NoError(os.Mkdir(unauthorizedDir, 0o755))
					copyFile(t, filepath.Join(tmpDir, coordinatorCertFileDefault), filepath.Join(unauthorizedDir, coordinatorCertFileDefault))
					copyFile(t, filepath.Join(tmpDir, manifestFile), filepath.Join(unauthorizedDir, manifestFile))

					pub, priv := manifest.GenerateKey(t)
					crt := manifest.GenerateCertificate(t, priv)

					privEncoded, err := x509.MarshalPKCS8PrivateKey(priv)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(unauthorizedDir, keyFileDefault), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))
					require.NoError(os.WriteFile(filepath.Join(unauthorizedDir, publicKeyFileDefault), pub, 0o644))
					require.NoError(os.WriteFile(filepath.Join(unauthorizedDir, certFileDefault), crt, 0o644))
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Attempting to read secrets as unauthorized user")
					assert := assert.New(t)
					tmpDir = filepath.Join(tmpDir, "unauthorized")

					_, err := readSecret(ctx, t, kubectl, cmd, manifest.DefaultUserSecret, namespace, tmpDir, true)
					assert.Error(err)
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace, _ string) {
					t.Log("Attempting to read secrets without providing TLS certificates")
					forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
						req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://localhost:%s/secrets?s=%s", port, manifest.DefaultUserSecret), http.NoBody)
						if err != nil {
							return err
						}

						client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
						resp, err := client.Do(req)
						if err != nil {
							return err
						}
						resp.Body.Close()
						if resp.StatusCode != http.StatusUnauthorized {
							return fmt.Errorf("expected HTTP code %d, got %d", http.StatusUnauthorized, resp.StatusCode)
						}
						return nil
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Attempting to set secrets as unauthorized user")
					require := require.New(t)
					tmpDir = filepath.Join(tmpDir, "unauthorized")

					newSecrets := map[string]oss_mnf.UserSecret{
						"UserKey": {Key: bytes.Repeat([]byte{0x01}, 128/8)},
					}

					secretsJSON, err := json.MarshalIndent(newSecrets, "", "  ")
					require.NoError(err)
					secretPath := filepath.Join(tmpDir, "secrets.json")
					require.NoError(os.WriteFile(secretPath, secretsJSON, 0o644))

					t.Logf("Uploading user defined secret: %s", secretsJSON)
					forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
						_, err = cmd.Run(
							ctx,
							"secret", "set",
							secretPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						if err == nil {
							return errors.New("expected error, got nil")
						}
						return nil
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Attempting to set secrets without providing TLS certificates")
					forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
						secretFile, err := os.Open(filepath.Join(tmpDir, "unauthorized", "secrets.json"))
						require.NoError(t, err)
						defer secretFile.Close()

						req, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("https://localhost:%s/secrets?s=%s", port, manifest.DefaultUserSecret), secretFile)
						if err != nil {
							return err
						}
						req.Header.Set("Content-Type", "application/json")

						client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
						resp, err := client.Do(req)
						if err != nil {
							return err
						}
						resp.Body.Close()
						if resp.StatusCode != http.StatusUnauthorized {
							return fmt.Errorf("expected HTTP code %d, got %d", http.StatusUnauthorized, resp.StatusCode)
						}
						return nil
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Attempting to update manifest as unauthorized user")
					require := require.New(t)
					tmpDir = filepath.Join(tmpDir, "unauthorized")

					// Create Update Manifest
					mnf := manifest.Manifest{
						Packages: map[string]manifest.PackageProperties{
							manifest.DefaultPackage: {SecurityVersion: 999},
						},
					}
					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					// Upload update manifest
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						if err == nil {
							return errors.New("expected error, got nil")
						}
						return nil
					})
				})

				return actions
			}(),
		},
		"threshold manifest update": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				_, user2Key := manifest.GenerateKey(t)
				user2Cert := manifest.GenerateCertificate(t, user2Key)
				user2KeyName := filepath.Join("user2", keyFileDefault)
				user2CertName := filepath.Join("user2", certFileDefault)

				_, user3Key := manifest.GenerateKey(t)
				user3Cert := manifest.GenerateCertificate(t, user3Key)
				user3KeyName := filepath.Join("user3", keyFileDefault)
				user3CertName := filepath.Join("user3", certFileDefault)

				// Write second user's key and cert to tmpDir
				actions = append(actions, func(_ context.Context, t *testing.T, _ *kubectl.Kubectl, _ *cmd.Cmd, _, tmpDir string) {
					require := require.New(t)

					// Write user key and cert
					require.NoError(os.MkdirAll(filepath.Join(tmpDir, "user2"), 0o755))
					privEncoded, err := x509.MarshalPKCS8PrivateKey(user2Key)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user2KeyName), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user2CertName), user2Cert, 0o644))
				})

				// Write third user's key and cert to tmpDir
				actions = append(actions, func(_ context.Context, t *testing.T, _ *kubectl.Kubectl, _ *cmd.Cmd, _, tmpDir string) {
					require := require.New(t)

					// Write user key and cert
					require.NoError(os.MkdirAll(filepath.Join(tmpDir, "user3"), 0o755))
					privEncoded, err := x509.MarshalPKCS8PrivateKey(user3Key)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user3KeyName), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))
					require.NoError(os.WriteFile(filepath.Join(tmpDir, user3CertName), user3Cert, 0o644))
				})

				// Update manifest to add the new users and a new group for them
				// The new manifest should require only 1 acknowledgement to update
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnfRaw, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
					require.NoError(err)
					var mnf manifest.Manifest
					require.NoError(json.Unmarshal(mnfRaw, &mnf))

					mnf.Roles["AlsoUpdateManifest"] = oss_mnf.Role{
						ResourceType: "Manifest",
						Actions:      []string{"UpdateManifest"},
					}

					mnf.Users["user2"] = oss_mnf.User{
						Certificate: string(user2Cert),
						Roles:       []string{"AlsoUpdateManifest", manifest.DefaultUpdatePackageRole},
					}
					mnf.Users["user3"] = oss_mnf.User{
						Certificate: string(user3Cert),
						Roles:       []string{"AlsoUpdateManifest", manifest.DefaultUpdatePackageRole},
					}
					mnf.Config.UpdateThreshold = 1 // Only a single user should be required to update the manifest

					mnfRaw, err = json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Apply an update to the manifest
				// Because the threshold is set to 1, it should be applied immediately
				// without requiring acknowledgement from the new users
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)

					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["package2"] = manifest.PackageProperties{
						UniqueID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					}

					// Set the update threshold to 2 so future updates require 2 acknowledgements
					mnf.Config.UpdateThreshold = 2

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Verify the update was applied
				verifyUpdateAction := func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)
					assert := assert.New(t)

					expectedMnf, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
					require.NoError(err)
					actualMnfFile := filepath.Join(tmpDir, "current.json")

					forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
						t.Logf("Checking manifest on %q", pod)
						if _, err := cmd.Run(
							ctx,
							"manifest", "get",
							net.JoinHostPort(localhost, port),
							"--output", actualMnfFile,
							eraConfig,
						); err != nil {
							return err
						}

						actualMnf, err := os.ReadFile(actualMnfFile)
						require.NoError(err)
						assert.Equal(expectedMnf, actualMnf)
						return nil
					})
				}

				actions = append(actions, verifyUpdateAction)

				// Apply a second update to the manifest
				// Because the threshold is now set to 2, it should not be applied immediately
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)

					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["package3"] = manifest.PackageProperties{
						UniqueID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					}

					// Set the update threshold to 0 so future updates require acknowledgements from all users
					mnf.Config.UpdateThreshold = 0

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Verify the pending update
				actions = append(actions, verifyPendingUpdates("update.json"))

				// Acknowledge the update as user2
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					updateAcknowledge(ctx, t, kubectl, cmd, namespace, tmpDir, "update.json", user2CertName, user2KeyName, 0)
				})

				actions = append(actions, verifyUpdateAction)

				// Apply a third update to the manifest
				// Because the threshold is now set to 0, it should not be applied immediately,
				// but require all users to acknowledge the update
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					require := require.New(t)

					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["package4"] = manifest.PackageProperties{
						UniqueID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Verify the pending update
				actions = append(actions, verifyPendingUpdates("update.json"))

				// Acknowledge the update as user2
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					updateAcknowledge(ctx, t, kubectl, cmd, namespace, tmpDir, "update.json", user2CertName, user2KeyName, 1)
				})

				// Verify the pending update
				actions = append(actions, verifyPendingUpdates("update.json"))

				// Acknowledge the update as user3
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					updateAcknowledge(ctx, t, kubectl, cmd, namespace, tmpDir, "update.json", user3CertName, user3KeyName, 0)
				})

				actions = append(actions, verifyUpdateAction)

				return actions
			}(),
		},
		"sealed key state binding": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				mnf.RecoveryKeys[manifest.DefaultUser2] = mnf.RecoveryKeys[manifest.DefaultUser]
				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				// Get a backup of the sealed key
				var sealedKeyBackup []byte
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace, _ string) {
					t.Log("Retrieving sealed key")
					secret, err := kubectl.GetSecretData(ctx, namespace, stateSecretName)
					require.NoError(t, err)
					sealedKeyBackup = secret[stdstore.SealedKeyFname]
				})

				// Update the manifest to update the state
				// This will re-seal the state and key
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.Packages["newPackage"] = manifest.PackageProperties{
						Debug:    true,
						UniqueID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, manifestFile), mnfRaw, 0o644))
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfRaw, certFileDefault, keyFileDefault)
				})

				// Scale down Coordinators to 0
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace string, _ string) {
					t.Log("Scaling down Coordinator deployment to 0")
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
				})

				// Apply the sealed key backup
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace, _ string) {
					t.Log("Retrieving current sealed state")
					secret, err := kubectl.GetSecretData(ctx, namespace, stateSecretName)
					require.NoError(t, err)

					secret[stdstore.SealedKeyFname] = sealedKeyBackup

					t.Log("Updating sealed state with key from backup")
					require.NoError(t, kubectl.UpdateSecret(ctx, namespace, stateSecretName, secret))
				})

				// Scale back up
				// Since the sealed key does not match the sealed data, the Coordinator should be in recovery mode
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					t.Log("Scaling up Coordinator deployment to 1")
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 1))

					getStatus(ctx, t, kubectl, cmd, namespace, state.Recovery)
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, tmpDir string) {
					recoverCoordinator(ctx, t, kubectl, cmd, manifest.DefaultUser2, keyFileDefault, namespace, tmpDir)
				})
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifyManifestHasntChangedAction(manifestFile))

				// Run all test actions again to verify the recovered Coordinator behaves the same
				actions = append(actions, actions...)

				return actions
			}(),
		},
		"update recovery keys 1 to 2": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace string, _ string) {
					if *replicas < 2 {
						t.Skipf("Skipping test, requires at least 2 replicas, got %d", *replicas)
					}
				})

				var pods []string
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, _ *cmd.Cmd, namespace string, _ string) {
					var err error
					pods, err = kubectl.GetAvailablePodNamesForDeployment(ctx, namespace, coordinatorDeployment)
					require.NoError(t, err)
					require.GreaterOrEqual(t, len(pods), 2, "expected at least 2 pods for coordinator deployment")
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Creating new recovery keys")
					require := require.New(t)
					recPub1, recPriv1 := manifest.GenerateKey(t)
					recPub2, recPriv2 := manifest.GenerateKey(t)

					priv1Encoded, err := x509.MarshalPKCS8PrivateKey(recPriv1)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, "rec1.priv"), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: priv1Encoded,
					}), 0o644))

					priv2Encoded, err := x509.MarshalPKCS8PrivateKey(recPriv2)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, "rec2.priv"), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: priv2Encoded,
					}), 0o644))

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.RecoveryKeys = map[string]string{
						"recovery1": string(recPub1),
						"recovery2": string(recPub2),
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					// Upload update manifest to first Pod in list
					withPortForward(ctx, t, kubectl, namespace, pods[0], coordinatorClientPort, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							"--recoverydata", filepath.Join(tmpDir, "newRecoveryData.bin"),
							eraConfig,
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Setting another update manifest")
					require := require.New(t)

					mnfJSON, err := os.ReadFile(filepath.Join(tmpDir, "update.json"))
					require.NoError(err)
					var mnf manifest.Manifest
					require.NoError(json.Unmarshal(mnfJSON, &mnf))

					mnf.Packages["anotherPackage"] = manifest.PackageProperties{
						UniqueID: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting second update manifest:\n%s", mnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update2.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					// Upload update manifest to second Pod in list
					// The instance receiving this update should be a different one from the one that received
					// the recovery key update, i.e. this instance did not update its recovery data directly.
					// Recovery must still work with the new keys after this instance sealed the state.
					withPortForward(ctx, t, kubectl, namespace, pods[1], coordinatorClientPort, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Scaling Coordinator deployment to 0")

					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					t.Log("Scaling Coordinator deployment back up. Should recover automatically")
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))

					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				// Now trigger recovery and recover with our new keys
				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)
					recoveryJSON, err := os.ReadFile(filepath.Join(tmpDir, "newRecoveryData.bin"))
					require.NoError(err)

					t.Logf("Parsing recovery data from %s", recoveryJSON)
					encryptedRecoveryKey1File := filepath.Join(tmpDir, "encrypted_recovery_key_1")
					encryptedRecoveryKey2File := filepath.Join(tmpDir, "encrypted_recovery_key_2")
					encryptedRecoveryData := map[string]map[string][]byte{}
					require.NoError(json.Unmarshal(recoveryJSON, &encryptedRecoveryData))
					keyMap := encryptedRecoveryData["RecoverySecrets"]
					require.NoError(os.WriteFile(encryptedRecoveryKey1File, keyMap["recovery1"], 0o644))
					require.NoError(os.WriteFile(encryptedRecoveryKey2File, keyMap["recovery2"], 0o644))

					t.Log("Recovering Coordinator with first key")
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"recover",
							encryptedRecoveryKey1File,
							net.JoinHostPort(localhost, port),
							eraConfig,
							"--key", filepath.Join(tmpDir, "rec1.priv"),
						)
						return err
					})

					t.Log("Recovering Coordinator with second key")
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"recover",
							encryptedRecoveryKey2File,
							net.JoinHostPort(localhost, port),
							eraConfig,
							"--key", filepath.Join(tmpDir, "rec2.priv"),
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				return actions
			}(),
		},
		"update recovery keys none to 1": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				mnf.RecoveryKeys = nil
				return mnf
			},
			actions: func() []testAction {
				var actions []testAction
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Creating new recovery keys")
					require := require.New(t)
					recPub, recPriv := manifest.GenerateKey(t)

					privEncoded, err := x509.MarshalPKCS8PrivateKey(recPriv)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, "rec1.priv"), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.RecoveryKeys = map[string]string{
						"recovery1": string(recPub),
					}

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					// Upload update manifest
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							"--recoverydata", filepath.Join(tmpDir, "newRecoveryData.bin"),
							eraConfig,
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Scaling Coordinator deployment to 0")

					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					t.Log("Scaling Coordinator deployment back up. Should recover automatically")
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))

					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				// Now trigger recovery and recover with our new key
				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					require := require.New(t)
					recoveryJSON, err := os.ReadFile(filepath.Join(tmpDir, "newRecoveryData.bin"))
					require.NoError(err)

					t.Logf("Parsing recovery data from %s", recoveryJSON)
					encryptedRecoveryKeyFile := filepath.Join(tmpDir, "encrypted_recovery_key")
					encryptedRecoveryData := map[string]map[string][]byte{}
					require.NoError(json.Unmarshal(recoveryJSON, &encryptedRecoveryData))
					keyMap := encryptedRecoveryData["RecoverySecrets"]
					require.NoError(os.WriteFile(encryptedRecoveryKeyFile, keyMap["recovery1"], 0o644))

					t.Log("Recovering Coordinator with first key")
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"recover",
							encryptedRecoveryKeyFile,
							net.JoinHostPort(localhost, port),
							eraConfig,
							"--key", filepath.Join(tmpDir, "rec1.priv"),
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				return actions
			}(),
		},
		"update recovery keys 2 to 1": {
			getStartingManifest: func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
				mnf := manifest.DefaultManifest(crt, key, defaultPackage)
				recPub, _ := manifest.GenerateKey(t)
				mnf.RecoveryKeys["additional_key"] = string(recPub)
				return mnf
			},
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Removing a recovery key")
					require := require.New(t)

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					delete(mnf.RecoveryKeys, "additional_key")

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					// Upload update manifest
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							"--recoverydata", filepath.Join(tmpDir, recoveryDataFile),
							eraConfig,
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Scaling Coordinator deployment to 0")

					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					t.Log("Scaling Coordinator deployment back up. Should recover automatically")
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))

					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifyManifestHasntChangedAction("update.json"))

				return actions
			}(),
		},
		"remove recovery keys": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Removing all recovery keys")
					require := require.New(t)

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.RecoveryKeys = nil

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					// Upload update manifest
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, keyFileDefault),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							eraConfig,
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Scaling Coordinator deployment to 0")

					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					t.Log("Scaling Coordinator deployment back up. Should recover automatically")
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))

					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				return actions
			}(),
		},
		"update single recovery key": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Updating a single recovery key")
					require := require.New(t)
					recPub, recPriv := manifest.GenerateKey(t)

					require.NoError(os.Rename(filepath.Join(tmpDir, keyFileDefault), filepath.Join(tmpDir, "priv.key")))

					privEncoded, err := x509.MarshalPKCS8PrivateKey(recPriv)
					require.NoError(err)
					require.NoError(os.WriteFile(filepath.Join(tmpDir, keyFileDefault), pem.EncodeToMemory(&pem.Block{
						Type:  "PRIVATE KEY",
						Bytes: privEncoded,
					}), 0o644))

					// Create Update Manifest
					mnf := loadTestManifest(require, tmpDir)
					mnf.RecoveryKeys[manifest.DefaultUser] = string(recPub)

					mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)
					t.Logf("Setting update manifest:\n%s", mnfRaw)
					updateMnfPath := filepath.Join(tmpDir, "update.json")
					require.NoError(os.WriteFile(updateMnfPath, mnfRaw, 0o644))

					recoveryDataFile := filepath.Join(tmpDir, recoveryDataFile)
					require.NoError(os.Remove(recoveryDataFile))

					// Upload update manifest
					withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
						_, err := cmd.Run(
							ctx,
							"manifest", "update", "apply",
							updateMnfPath, net.JoinHostPort(localhost, port),
							"--key", filepath.Join(tmpDir, "priv.key"),
							"--cert", filepath.Join(tmpDir, certFileDefault),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
							"--recoverydata", recoveryDataFile,
							eraConfig,
						)
						return err
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Scaling Coordinator deployment to 0")

					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, 0))
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace string, _ string) {
					t.Log("Scaling Coordinator deployment back up. Should recover automatically")
					require.NoError(t, kubectl.ScaleDeployment(ctx, namespace, coordinatorDeployment, *replicas))

					getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)
				})

				actions = append(actions, triggerRecoveryActions...)
				actions = append(actions, recoverCoordinatorActions...)
				actions = append(actions, verifyManifestHasntChangedAction("update.json"))
				return actions
			}(),
		},
		"rotate root secret": {
			getStartingManifest: manifest.DefaultManifest,
			actions: func() []testAction {
				var actions []testAction

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
						res, err := cmd.Run(ctx,
							"status", net.JoinHostPort(localhost, port),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
						)
						if err != nil {
							return err
						}
						if !strings.Contains(res, fmt.Sprintf("%d: Coordinator is running correctly and ready to accept marbles", state.AcceptingMarbles)) {
							return fmt.Errorf("Coordinator not in expected state: %s", res)
						}
						return nil
					})
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Updating manifest and rotating root secret")
					require := require.New(t)
					mnf := loadTestManifest(require, tmpDir)
					mnf.Config.RotateRootSecret = true

					mnfJSON, err := json.MarshalIndent(mnf, "", "  ")
					require.NoError(err)

					updateManifest(ctx, t, kubectl, cmd, namespace, tmpDir, mnfJSON, certFileDefault, keyFileDefault)
				})

				actions = append(actions, func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
					t.Log("Testing old certificate against new Coordinator")
					forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
						res, err := cmd.Run(ctx,
							"status", net.JoinHostPort(localhost, port),
							"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
						)
						if err != nil {
							return err
						}
						if !strings.Contains(res, fmt.Sprintf("%d: Coordinator is running correctly and ready to accept marbles", state.AcceptingMarbles)) {
							return fmt.Errorf("Coordinator not in expected state: %s", res)
						}
						return nil
					})
				})

				return actions
			}(),
		},
	}

	changeRecoveryTC := testCases["update recovery keys 1 to 2"]
	changeRecoveryTC.getStartingManifest = func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
		mnf := manifest.DefaultManifest(crt, key, defaultPackage)
		recPub, _ := manifest.GenerateKey(t)
		mnf.RecoveryKeys["additional_key"] = string(recPub)
		return mnf
	}
	testCases["update multiple recovery keys"] = changeRecoveryTC

	for _, sealMode := range []string{"Disabled", "ProductKey", "UniqueKey"} {
		tc := testCases["recover state"]
		tc.getStartingManifest = func(crt, key []byte, defaultPackage manifest.PackageProperties) manifest.Manifest {
			mnf := manifest.DefaultManifest(crt, key, defaultPackage)
			mnf.Config.SealMode = sealMode
			return mnf
		}
		testCases["recover state with seal mode "+sealMode] = tc
	}

	for n, tCase := range testCases {
		// Capture range variables
		tc := tCase
		name := n
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx, _, require, kubectl, cmd, tmpDir := createBaseObjects(t)
			t.Log("Starting test")

			pub, priv := manifest.GenerateKey(t)
			crt := manifest.GenerateCertificate(t, priv)

			privEncoded, err := x509.MarshalPKCS8PrivateKey(priv)
			require.NoError(err)
			require.NoError(os.WriteFile(filepath.Join(tmpDir, keyFileDefault), pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: privEncoded,
			}), 0o644))
			require.NoError(os.WriteFile(filepath.Join(tmpDir, publicKeyFileDefault), pub, 0o644))
			require.NoError(os.WriteFile(filepath.Join(tmpDir, certFileDefault), crt, 0o644))

			namespace := setManifest(ctx, t, kubectl, cmd, tmpDir, tc.getStartingManifest(crt, pub, marbleConfig), *replicas)
			getLogsOnFailure(t, kubectl, namespace)

			for _, action := range tc.actions {
				action(ctx, t, kubectl, cmd, namespace, tmpDir)
			}

			// Regression: verify that recovery data hasn't been lost
			secretData, err := kubectl.GetSecretData(ctx, namespace, stateSecretName)
			require.NoError(err)
			sealedData := secretData[stdstore.SealedDataFname]
			recoveryDataLen := binary.LittleEndian.Uint32(sealedData[:4])
			require.Greater(recoveryDataLen, uint32(0))
		})
	}
}

func setUpTest(t *testing.T, replicas int) (
	_ context.Context, _ *assert.Assertions, _ *require.Assertions, _ *kubectl.Kubectl, _ *cmd.Cmd, tmpDir, namespace string,
) {
	t.Helper()
	ctx, assert, require, kubectl, cmd, tmpDir := createBaseObjects(t)
	namespace, releaseName := setUpNamespace(ctx, t, kubectl)
	installChart(ctx, t, namespace, releaseName, replicas)

	getLogsOnFailure(t, kubectl, namespace)

	return ctx, assert, require, kubectl, cmd, tmpDir, namespace
}

func createBaseObjects(t *testing.T) (
	_ context.Context, _ *assert.Assertions, _ *require.Assertions, _ *kubectl.Kubectl, _ *cmd.Cmd, tmpDir string,
) {
	t.Helper()

	assert := assert.New(t)
	require := require.New(t)

	kubectl, err := kubectl.New(t, *kubeConfigPath)
	require.NoError(err)

	cmd, err := cmd.New(t, *cliPath)
	require.NoError(err)

	tmpDir = t.TempDir()

	ctx, cancel := context.WithTimeout(context.Background(), defaultTimeout)
	t.Cleanup(cancel)

	return ctx, assert, require, kubectl, cmd, tmpDir
}

func setUpNamespace(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl) (namespace, releaseName string) {
	t.Helper()

	require := require.New(t)

	t.Logf("Setting up namespace")
	namespace = "marblerun"
	uid, cleanUp, err := kubectl.SetUpNamespace(ctx, namespace, *accessToken)
	require.NoError(err)
	t.Cleanup(cleanUp)

	namespace += "-" + uid
	releaseName = "marblerun-" + uid

	t.Logf("Test UID: %s", uid)
	t.Logf("Running test in namespace %q", namespace)

	return namespace, releaseName
}

func installChart(ctx context.Context, t *testing.T, namespace, releaseName string, replicas int) {
	t.Helper()

	require := require.New(t)

	helm, err := helm.New(t, *kubeConfigPath, namespace)
	require.NoError(err)
	t.Logf("Installing chart %q from %q", releaseName, *chartPath)
	uninstall, err := helm.InstallChart(ctx, releaseName, namespace, *chartPath, replicas, defaultTimeout, nil)
	require.NoError(err)
	t.Cleanup(uninstall)
}

func writeManifest(t *testing.T, mnf manifest.Manifest, tmpDir string) string {
	t.Helper()

	require := require.New(t)

	mnfRaw, err := json.MarshalIndent(mnf, "", "  ")
	require.NoError(err)
	t.Logf("Manifest:\n%s", mnfRaw)
	manifestPath := filepath.Join(tmpDir, manifestFile)
	require.NoError(os.WriteFile(manifestPath, mnfRaw, 0o644))

	return manifestPath
}

// withPortForward forwards a port and runs a given function using that connection.
// Should port forwarding fail, or the function return an error, port forwarding and the function will be retried.
func withPortForward(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, namespace, pod, port string,
	fn func(port string) error,
) {
	t.Helper()

	require.Eventually(t, func() bool {
		pfPort, pfCancel, err := kubectl.PortForwardPod(ctx, namespace, pod, port)
		if err != nil {
			t.Logf("Port forwarding failed: %s", err)
			return false
		}
		defer pfCancel()

		if err := fn(pfPort); err != nil {
			t.Logf("Function failed: %s", err)
			return false
		}
		return true
	}, eventuallyTimeout, eventuallyInterval)

	t.Logf("Condition satisfied for pod %q", pod)
}

// withPortForwardAny picks a random pod of the Coordinator deployment and uses that pod to run [withPortForward].
func withPortForwardAny(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, namespace string,
	fn func(port string) error,
) {
	t.Helper()
	require := require.New(t)

	pods, err := kubectl.GetAvailablePodNamesForDeployment(ctx, namespace, coordinatorDeployment)
	require.NoError(err)
	pod := pods[rand.Intn(len(pods))]

	withPortForward(ctx, t, kubectl, namespace, pod, coordinatorClientPort, fn)
}

func setManifest(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd,
	tmpDir string, mnf manifest.Manifest, replicas int,
) string {
	namespace, releaseName := setUpNamespace(ctx, t, kubectl)
	manifestPath := writeManifest(t, mnf, tmpDir)
	installChart(ctx, t, namespace, releaseName, replicas)

	// Verify all instances are accepting a manifest
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingManifest)

	// Set manifest for any Coordinator instance
	t.Log("Setting manifest")
	withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
		_, err := cmd.Run(
			ctx,
			"manifest", "set",
			manifestPath, net.JoinHostPort(localhost, port),
			"--recoverydata", filepath.Join(tmpDir, recoveryDataFile),
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)
		return err
	})
	t.Log("Manifest set")

	// Verify all instances are accepting marbles
	getStatus(ctx, t, kubectl, cmd, namespace, state.AcceptingMarbles)

	return namespace
}

func getStatus(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl,
	cmd *cmd.Cmd, namespace string, wantStatus state.State,
) {
	t.Helper()

	// Check status of all MarbleRun instances
	forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
		t.Logf("Getting status of pod %q", pod)
		return getStatusOfInstance(ctx, t, cmd, port, wantStatus)
	})
}

func getStatusOfInstance(
	ctx context.Context, t *testing.T, cmd *cmd.Cmd, port string, wantStatus state.State,
) error {
	t.Helper()

	status, err := cmd.GetStatus(ctx, net.JoinHostPort(localhost, port))
	if err != nil {
		return fmt.Errorf("getting status: %w", err)
	}
	if status != wantStatus {
		return fmt.Errorf("got status %q, want %q", status, wantStatus)
	}
	return nil
}

// updateManifest performs a manifest update.
func updateManifest(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd,
	namespace, tmpDir string, updateMnf []byte, certName, keyName string,
) {
	updateMnfPath := filepath.Join(tmpDir, "update.json")
	require.NoError(t, os.WriteFile(updateMnfPath, updateMnf, 0o644))

	// Upload update manifest
	withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
		_, err := cmd.Run(
			ctx,
			"manifest", "update", "apply",
			updateMnfPath, net.JoinHostPort(localhost, port),
			"--key", filepath.Join(tmpDir, keyName),
			"--cert", filepath.Join(tmpDir, certName),
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)
		return err
	})
}

func updateAcknowledge(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd,
	namespace, tmpDir, manifestFile, certName, keyName string, wantMissing int,
) {
	withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
		out, err := cmd.Run(
			ctx,
			"manifest", "update", "acknowledge",
			filepath.Join(tmpDir, manifestFile),
			net.JoinHostPort(localhost, port),
			"--key", filepath.Join(tmpDir, keyName),
			"--cert", filepath.Join(tmpDir, certName),
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)
		if err != nil {
			return err
		}
		switch wantMissing {
		case 0:
			require.Contains(t, out, "Update successful")
		case 1:
			require.Contains(t, out, "1 user still needs to acknowledge the update")
		default:
			require.Contains(t, out, fmt.Sprintf("%d users still need to acknowledge the update", wantMissing))
		}
		return nil
	})
}

// setSecret sets the given secret on a random Coordinator instance.
// The secret is written to tmpDir/secrets.json.
// The function returns an error if (and only if) an error occurred while setting the secret using the CLI.
func setSecret(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd,
	namespace, tmpDir, certName, keyName string, secret map[string]oss_mnf.UserSecret, //nolint:unparam
) {
	require := require.New(t)

	secretsJSON, err := json.MarshalIndent(secret, "", "  ")
	require.NoError(err)
	secretPath := filepath.Join(tmpDir, "secrets.json")
	require.NoError(os.WriteFile(secretPath, secretsJSON, 0o644))

	t.Logf("Uploading user defined secret: %s", secretsJSON)
	withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
		_, err = cmd.Run(
			ctx,
			"secret", "set",
			secretPath, net.JoinHostPort(localhost, port),
			"--key", filepath.Join(tmpDir, keyName),
			"--cert", filepath.Join(tmpDir, certName),
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)
		return err
	})
}

// readSecret tries to read the secret with the given name from all available Coordinator instances.
// The secret is written to tmpDir.
// The final error returned (if any) is a combination of all errors that occurred while trying to read the secret.
func readSecret(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd,
	secretName, namespace, tmpDir string, wantErr bool,
) ([]string, error) {
	var errs []error
	var filenames []string

	forAllPods(ctx, t, kubectl, namespace, func(pod, port string) error {
		filename := filepath.Join(tmpDir, fmt.Sprintf("output-%s.json", pod))
		_, err := cmd.Run(
			ctx,
			"secret", "get",
			secretName, net.JoinHostPort(localhost, port),
			"--key", filepath.Join(tmpDir, keyFileDefault),
			"--cert", filepath.Join(tmpDir, certFileDefault),
			"--output", filename,
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)

		if !wantErr && err != nil {
			return err
		}

		if err != nil {
			errs = append(errs, err)
		} else {
			filenames = append(filenames, filename)
		}

		return nil
	})

	return filenames, errors.Join(errs...)
}

// readAndVerifySecret reads the secret with the given name from all available Coordinator instances and verifies its value.
func readAndVerifySecret(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd,
	secretName, namespace, tmpDir string, expected []byte,
) {
	assert := assert.New(t)
	require := require.New(t)

	filenames, err := readSecret(ctx, t, kubectl, cmd, secretName, namespace, tmpDir, false)
	require.NoError(err)

	for _, filename := range filenames {
		out, err := os.ReadFile(filename)
		require.NoError(err)

		t.Logf("Secret from %q :\n%s", filename, out)
		var secret map[string]oss_mnf.Secret
		require.NoError(json.Unmarshal(out, &secret))
		assert.Equal(expected, []byte(secret[secretName].Private))
	}
}

// verifyNoPendingUpdates verifies that all MarbleRun instances have no pending updates.
func verifyNoPendingUpdates(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string,
) {
	// Verify all MarbleRun instances have no pending update
	t.Log("Verifying no instance has pending updates")

	forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
		_, err := cmd.Run(
			ctx,
			"manifest", "update", "get",
			net.JoinHostPort(localhost, port),
			"--missing",
			"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
			eraConfig,
		)
		if !strings.Contains(err.Error(), "no update in progress") {
			return fmt.Errorf("expected no update in progress error, got %q", err.Error())
		}
		return nil
	})
}

// verifyPendingUpdates verifies that all MarbleRun instances have a pending update.
func verifyPendingUpdates(manifestFile string) func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
	return func(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, namespace, tmpDir string) {
		require := require.New(t)
		assert := assert.New(t)

		// Verify all MarbleRun instances have a pending update
		t.Log("Verifying pending update")
		expectedMnf, err := os.ReadFile(filepath.Join(tmpDir, manifestFile))
		require.NoError(err)

		forAllPods(ctx, t, kubectl, namespace, func(_, port string) error {
			pendingMnfFile := filepath.Join(tmpDir, "pending.json")
			if _, err := cmd.Run(
				ctx,
				"manifest", "update", "get",
				net.JoinHostPort(localhost, port),
				"--output", pendingMnfFile,
				"--coordinator-cert", filepath.Join(tmpDir, coordinatorCertFileDefault),
				eraConfig,
			); err != nil {
				return err
			}

			actualMnf, err := os.ReadFile(pendingMnfFile)
			require.NoError(err)
			assert.Equal(expectedMnf, actualMnf)
			return nil
		})
	}
}

func forAllPods(ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, namespace string, do func(_, port string) error) {
	t.Helper()
	require := require.New(t)

	coordinatorPods, err := kubectl.GetAvailablePodNamesForService(ctx, namespace, coordinatorClientService)
	require.NoError(err)

	for _, pod := range coordinatorPods {
		require.Eventually(func() bool {
			port, pfCancel, err := kubectl.PortForwardPod(ctx, namespace, pod, coordinatorClientPort)
			if err != nil {
				t.Logf("Port forwarding failed for pod %s: %s. Retrying...", pod, err)
				return false
			}
			defer pfCancel()

			if err := do(pod, port); err != nil {
				t.Logf("Action failed for pod %s: %s. Retrying...", pod, err)
				return false
			}
			return true
		}, eventuallyTimeout, eventuallyInterval, "Failed to eventually execute action for pod")
	}
}

// recoverCoordinator recovers the state of a Coordinator instance.
// The recovery data of a user is decrypted using the private key from keyFile.
func recoverCoordinator(
	ctx context.Context, t *testing.T, kubectl *kubectl.Kubectl, cmd *cmd.Cmd, user, keyFile, namespace, tmpDir string, //nolint:unparam
) {
	require := require.New(t)
	recoveryJSON, err := os.ReadFile(filepath.Join(tmpDir, recoveryDataFile))
	require.NoError(err)

	t.Logf("Parsing recovery data from %s", recoveryJSON)
	encryptedRecoveryKeyFile := filepath.Join(tmpDir, "encrypted_recovery_key")
	encryptedRecoveryData := map[string]map[string][]byte{}
	require.NoError(json.Unmarshal(recoveryJSON, &encryptedRecoveryData))
	keyMap := encryptedRecoveryData["RecoverySecrets"]
	require.NoError(os.WriteFile(encryptedRecoveryKeyFile, keyMap[user], 0o644))

	t.Log("Recovering Coordinator")
	withPortForwardAny(ctx, t, kubectl, namespace, func(port string) error {
		_, err := cmd.Run(
			ctx,
			"recover",
			encryptedRecoveryKeyFile,
			net.JoinHostPort(localhost, port),
			eraConfig,
			"--key", filepath.Join(tmpDir, keyFile),
		)
		return err
	})
}

// loadTestManifest loads the default manifest file from the given directory.
func loadTestManifest(require *require.Assertions, dir string) manifest.Manifest {
	bytes, err := os.ReadFile(filepath.Join(dir, manifestFile))
	require.NoError(err)

	var mnf manifest.Manifest
	require.NoError(json.Unmarshal(bytes, &mnf))
	return mnf
}

// getCoordinatorUpdateImage gets the image to use for the Coordinator update tests based on the current image name.
func getCoordinatorUpdateImage(t *testing.T, imageName string) string {
	t.Log("Current Coordinator image:", imageName)
	imageName, _, _ = strings.Cut(imageName, "@") // remove digest
	imageName += *coordinatorUpdateImageSuffix
	t.Log("Update Coordinator image:", imageName)
	if *coordinatorUpdateImageSuffix == "" {
		t.Log("coordinator-update-image-suffix not set. This test won't be fully meaningful.")
		// Let the test run anyway. The changed image name will at least trigger a rolling restart of the pods.
		markAsSkippedIfPasses(t)
	}
	return imageName
}

// markAsSkippedIfPasses marks a test as skipped if (and only if) it passes.
func markAsSkippedIfPasses(t *testing.T) {
	t.Cleanup(t.SkipNow)
}

func getLogsOnFailure(t *testing.T, kubectl *kubectl.Kubectl, namespace string) {
	t.Cleanup(func() {
		if !t.Failed() {
			return
		}

		logs, err := kubectl.GetLogsFromNamespace(context.Background(), namespace)
		if err != nil {
			t.Logf("Failed retrieving logs from namespace %q on failed test: %s", namespace, err)
			return
		}

		for podName, log := range logs {
			fileName := strings.ReplaceAll(fmt.Sprintf("%s-%s.log", t.Name(), podName), "/", "_")
			if err := os.WriteFile(fileName, log, 0o644); err != nil {
				t.Logf("Failed writing logs for pod %q: %s", podName, err)
			}
		}
	})
}

type logEntry struct {
	User       string `json:"user"`
	Package    string `json:"package"`
	NewVersion uint   `json:"new version"`
}

func parseUpdateLog(log []byte) ([]logEntry, error) {
	// Convert log to JSON array by adding commas between log entries
	log = []byte(fmt.Sprintf("[%s]", strings.ReplaceAll(string(log), "}\n{", "},{")))

	var logEntries []logEntry
	if err := json.Unmarshal(log, &logEntries); err != nil {
		return nil, err
	}
	return logEntries, nil
}

func copyFile(t *testing.T, src string, dst string) {
	require := require.New(t)
	data, err := os.ReadFile(src)
	require.NoError(err)
	require.NoError(os.WriteFile(dst, data, 0o644))
}

func createMarblePod(ctx context.Context, kubectl *kubectl.Kubectl, namespace, marbleType string, args []string, env map[string]string) (string, error) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "marble-pod-",
			Namespace:    namespace,
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{
				{
					Name:  "marble",
					Image: fmt.Sprintf("%s:%s", *marbleImageName, *marbleImageVersion),
					Args:  args,
					Env: func() []corev1.EnvVar {
						var envVars []corev1.EnvVar
						for k, v := range env {
							envVars = append(envVars, corev1.EnvVar{Name: k, Value: v})
						}
						envVars = append(
							envVars,
							corev1.EnvVar{Name: "EDG_TEST_ADDR", Value: net.JoinHostPort("0.0.0.0", marbleClientPort)},
							corev1.EnvVar{Name: "EDG_MARBLE_TYPE", Value: marbleType},
							corev1.EnvVar{Name: "EDG_MARBLE_COORDINATOR_ADDR", Value: fmt.Sprintf("coordinator-mesh-api.%s.svc.cluster.local:2001", namespace)},
						)

						return envVars
					}(),
					Ports: []corev1.ContainerPort{
						{
							Name:          "http",
							ContainerPort: marbleClientPortInt,
						},
					},
					Resources: corev1.ResourceRequirements{
						Limits: corev1.ResourceList{
							k8sutil.IntelEpc:       resource.MustParse("1Mi"),
							k8sutil.IntelEnclave:   resource.MustParse("1"),
							k8sutil.IntelProvision: resource.MustParse("1"),
						},
						Requests: corev1.ResourceList{
							k8sutil.IntelEpc:       resource.MustParse("1Mi"),
							k8sutil.IntelEnclave:   resource.MustParse("1"),
							k8sutil.IntelProvision: resource.MustParse("1"),
						},
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "dcap-conf",
							MountPath: "/etc/sgx_default_qcnl.conf",
							SubPath:   "sgx_default_qcnl.conf",
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "dcap-conf",
					VolumeSource: corev1.VolumeSource{
						ConfigMap: &corev1.ConfigMapVolumeSource{
							LocalObjectReference: corev1.LocalObjectReference{Name: "coordinator-dcap-config"},
						},
					},
				},
			},
		},
	}
	return kubectl.CreatePod(ctx, pod)
}
