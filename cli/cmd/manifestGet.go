package cmd

import (
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"reflect"

	"github.com/edgelesssys/marblerun/coordinator/manifest"
	"github.com/spf13/cobra"
	"github.com/tidwall/gjson"
)

func newManifestGet() *cobra.Command {
	var output string
	var consolidate bool
	var signature bool

	cmd := &cobra.Command{
		Use:   "get <IP:PORT>",
		Short: "Get the manifest from the Marblerun coordinator",
		Long: `Get the manifest from the Marblerun coordinator.
Optionally get the manifests signature or merge updates into the displayed manifest.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			hostName := args[0]
			cert, err := verifyCoordinator(hostName, eraConfig, insecureEra)
			if err != nil {
				return err
			}
			fmt.Println("Successfully verified coordinator, now requesting manifest")
			response, err := cliDataGet(hostName, "manifest", "data", cert)
			if err != nil {
				return err
			}
			manifest, err := decodeManifest(consolidate, gjson.GetBytes(response, "Manifest").String(), hostName, cert)
			if signature {
				// wrap the signature and manifest into one json object
				manifest = fmt.Sprintf("{\n\"ManifestSignature\": \"%s\",\n\"Manifest\": %s}", gjson.GetBytes(response, "ManifestSignature"), manifest)
			}

			if len(output) > 0 {
				return ioutil.WriteFile(output, []byte(manifest), 0644)
			}
			fmt.Println(manifest)
			return nil
		},
		SilenceUsage: true,
	}

	cmd.Flags().BoolVarP(&signature, "signature", "s", false, "Set to additionally display the manifests signature")
	cmd.Flags().BoolVarP(&consolidate, "consolidate", "c", false, "Set to merge updates into the displayed manifest")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Save singature to file instead of printing to stdout")
	return cmd
}

// decodeManifest parses a base64 encoded manifest and optionally merges updates
func decodeManifest(wantUpdate bool, encodedManifest, hostName string, cert []*pem.Block) (string, error) {
	manifest, err := base64.StdEncoding.DecodeString(encodedManifest)
	if err != nil {
		return "", err
	}

	if !wantUpdate {
		return string(manifest), nil
	}

	log, err := cliDataGet(hostName, "update", "data", cert)
	if err != nil {
		return "", err
	}

	return consolidateManifest(manifest, log)
}

// consolidateManifest updates a base manifest with values from an update log
func consolidateManifest(rawManifest, log []byte) (string, error) {
	var baseManifest manifest.Manifest
	if err := json.Unmarshal(rawManifest, &baseManifest); err != nil {
		return "", err
	}

	pkg := gjson.GetBytes(log, "..#.package").Array()
	svn := gjson.GetBytes(log, "..#.new version").Array()
	for idx, sPkg := range pkg {
		*baseManifest.Packages[sPkg.String()].SecurityVersion = uint(svn[idx].Uint())
	}

	updated, err := json.Marshal(baseManifest)
	if err != nil {
		return "", err
	}
	var removeTarget map[string]interface{}
	if err := json.Unmarshal(updated, &removeTarget); err != nil {
		return "", err
	}
	removeNil(removeTarget)
	updated, err = json.Marshal(removeTarget)
	if err != nil {
		return "", err
	}

	return gjson.Parse(string(updated)).Get(`@pretty:{"indent":"    "}`).String(), nil
}

func removeNil(m map[string]interface{}) {
	partial := reflect.ValueOf(m)
	for _, entry := range partial.MapKeys() {
		val := partial.MapIndex(entry)
		if val.IsNil() {
			delete(m, entry.String())
			continue
		}
		switch t := val.Interface().(type) {
		case map[string]interface{}:
			removeNil(t)
		}
	}
}
