package cmd

import (
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/c2h5oh/datasize"
	"github.com/edgelesssys/marblerun/util"
	"github.com/fatih/color"
	"github.com/pelletier/go-toml"
	"github.com/spf13/cobra"
)

// premainName is the name of the premain executable used
const premainName = "premain-graphene"

// uuidName is the file name of a Marble's uuid
const uuidName = "uuid"

// commentMarblerunAdditions holds the marker which is appended to the Graphene manifest before the performed additions
const commentMarblerunAdditions = "\n# MARBLERUN -- auto generated configuration entries \n"

// longDescription is the help text shown for this command
const longDescription = `Modifies a Graphene manifest for use with Marblerun.

This command tries to automatically adjust the required parameters in an already existing Graphene manifest template, simplifying the migration of your existing Graphene application to Marblerun.
Please note that you still need to manually create a Marblerun manifest.

For more information about the requirements and  changes performed, consult the documentation: https://www.marblerun.sh/docs/building-services/graphene/

The parameter of this command is the path of the Graphene manifest template you want to modify.
`

type diff struct {
	manifestEntry string
	alreadyExists bool
}

func newGraphenePrepareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graphene-prepare",
		Short: "Modifies a Graphene manifest for use with Marblerun",
		Long:  longDescription,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			fileName := args[0]

			return addToGrapheneManifest(fileName)
		},
		SilenceUsage: true,
	}

	return cmd
}

func addToGrapheneManifest(fileName string) error {
	// Read Graphene manifest and populate TOML tree
	fmt.Println("Reading file:", fileName)
	tree, err := toml.LoadFile(fileName)
	if os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %v", fileName)
	} else if err != nil {
		color.Red("ERROR: Cannot parse manifest. Have you selected the corrected file?")
		return err
	}

	// Parse tree for changes and generate maps with original entries & changes
	original, changes, err := parseTreeForChanges(tree)
	if err != nil {
		return err
	}

	// Calculate the differences, apply the changes
	return performChanges(calculateChanges(original, changes), fileName)
}

func parseTreeForChanges(tree *toml.Tree) (map[string]interface{}, map[string]interface{}, error) {
	// Create two maps, one with original values, one with the values we want to add or modify
	original := make(map[string]interface{})
	changes := make(map[string]interface{})

	// The values we want to search in the original manifest
	original["libos.entrypoint"] = tree.Get("libos.entrypoint")
	original["loader.insecure__use_host_env"] = tree.Get("loader.insecure__use_host_env")
	original["loader.argv0_override"] = tree.Get("loader.argv0_override")
	original["sgx.remote_attestation"] = tree.Get("sgx.remote_attestation")
	original["sgx.enclave_size"] = tree.Get("sgx.enclave_size")
	original["sgx.thread_num"] = tree.Get("sgx.thread_num")
	original["sgx.trusted_files.marblerun_premain"] = tree.Get("sgx.trusted_files.marblerun_premain")
	original["sgx.allowed_files.marblerun_uuid"] = tree.Get("sgx.allowed_files.marblerun_uuid")

	// Abort, if we cannot find an endpoint
	if original["libos.entrypoint"] == nil {
		return nil, nil, errors.New("cannot find libos.entrypoint")
	}

	// If Marblerun already touched the manifest, abort.
	if original["libos.entrypoint"].(string) == "file:"+premainName || original["sgx.trusted_files.marblerun_premain"] != nil || original["sgx.allowed_files.marblerun_uuid"] != nil {
		color.Yellow("The supplied manifest already contains changes for Marblerun. Have you selected the correct file?")
		return nil, nil, errors.New("manifest already contains Marblerun changes")
	}

	// Add premain-graphene executable as trusted file & entry point
	changes["libos.entrypoint"] = "file:" + premainName
	changes["sgx.trusted_files.marblerun_premain"] = "file:" + premainName

	// Set original endpoint as argv0. If one exists, keep the old one
	if original["loader.argv0_override"] == nil {
		fileEntry := strings.SplitAfter(original["libos.entrypoint"].(string), "file:")
		if len(fileEntry) != 2 {
			color.Red("ERROR: Cannot process the current entrypoint: %s", original["libos.entrypoint"].(string))
			color.Red("Note: This tool only supports 'file:' URIs for automatic modifcation.")
			color.Red("If you chose another type of path reference, please change it to 'file:' to continue.")
			color.Red("Otherwise, please file a bug report!")
			return nil, nil, fmt.Errorf("cannot determine entrypoint for argv0 override correctly")
		}
		changes["loader.argv0_override"] = fileEntry[1]
	}

	// Enable use "insecure" host env (which delegates the "secure" handling to Marblerun)
	if original["loader.insecure__use_host_env"] == nil || original["loader.insecure__use_host_env"].(int64) == 0 {
		changes["loader.insecure__use_host_env"] = 1
	}

	// Enable remote attestation
	if original["sgx.remote_attestation"] == nil || original["sgx.remote_attestation"].(int64) == 0 {
		changes["sgx.remote_attestation"] = 1
	}

	// Ensure at least 1024 MB of enclave memory for the premain Go runtime
	var v datasize.ByteSize
	if original["sgx.enclave_size"] != nil {
		v.UnmarshalText([]byte(original["sgx.enclave_size"].(string)))
	}
	if v.GBytes() < 1.00 {
		changes["sgx.enclave_size"] = "1024M"
	}

	// Ensure at least 16 SGX threads for the premain Go runtime
	if original["sgx.thread_num"] == nil || original["sgx.thread_num"].(int64) < 16 {
		changes["sgx.thread_num"] = 16
	}

	// Add Marble UUID to allowed files
	changes["sgx.allowed_files.marblerun_uuid"] = "file:" + uuidName

	return original, changes, nil
}

// calculateChanges takes two maps with TOML indices and values as input and calculates the difference between them
func calculateChanges(original map[string]interface{}, updates map[string]interface{}) []diff {
	var changeDiffs []diff
	// Note: This function only outputs entries which are defined in the original map.
	// This is designed this way as we need to check for each value if it already was set and if it was, if it was correct.
	// Defining new entries in "updates" is NOT intended here, and these values will be ignored.
	for index, originalValue := range original {
		if changedValue, ok := updates[index]; ok {
			// Add quotation marks for strings, direct value if not
			newDiff := diff{alreadyExists: originalValue != nil}
			// Add quotation marks for strings, direct value if not
			switch v := changedValue.(type) {
			case string:
				newDiff.manifestEntry = fmt.Sprintf("%s = \"%v\"", index, v)
			default:
				newDiff.manifestEntry = fmt.Sprintf("%s = %v", index, v)
			}
			changeDiffs = append(changeDiffs, newDiff)
		}
	}

	// Sort changes alphabetically
	sort.Slice(changeDiffs, func(i, j int) bool {
		return changeDiffs[i].manifestEntry < changeDiffs[j].manifestEntry
	})

	return changeDiffs
}

// performChanges displays the suggested changes to the user and tries to automatically perform them
func performChanges(changeDiffs []diff, fileName string) error {
	fmt.Println("\nMarblerun suggests the following changes to your Graphene manifest:")
	for _, entry := range changeDiffs {
		if entry.alreadyExists {
			color.Yellow(entry.manifestEntry)
		} else {
			color.Green(entry.manifestEntry)
		}
	}

	accepted, err := promptYesNo(os.Stdin, promptForChanges)
	if err != nil {
		return err
	}
	if !accepted {
		fmt.Println("Aborting.")
		return nil
	}

	directory := filepath.Dir(fileName)

	// Read Graphene manifest as normal text file
	manifestContentOriginal, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}

	// Perform modifications to manifest
	fmt.Println("Applying changes...")
	manifestContentModified, err := appendAndReplace(changeDiffs, manifestContentOriginal)
	if err != nil {
		return err
	}

	// Backup original manifest
	backupFileName := filepath.Base(fileName) + ".bak"
	fmt.Printf("Saving original manifest as %s...\n", backupFileName)
	if err := ioutil.WriteFile(filepath.Join(directory, backupFileName), manifestContentOriginal, 0644); err != nil {
		return err
	}

	// Write modified file to disk
	fileNameBase := filepath.Base(fileName)
	fmt.Printf("Saving changes to %s...\n", fileNameBase)
	if err := ioutil.WriteFile(fileName, manifestContentModified, 0644); err != nil {
		return err
	}

	fmt.Println("Downloading Marblerun premain from GitHub...")
	// Download Marblerun premain for Graphene from GitHub
	if err := downloadPremain(directory); err != nil {
		color.Red("ERROR: Cannot download '%s' from GitHub. Please add the file manually.", premainName)
	}

	fmt.Println("\nDone! You should be good to go for Marblerun!")

	return nil
}

func downloadPremain(directory string) error {
	cleanVersion := "v" + strings.Split(util.Version, "-")[0]

	// Download premain-graphene executable
	resp, err := http.Get(fmt.Sprintf("https://github.com/edgelesssys/marblerun/releases/download/%s/%s", cleanVersion, premainName))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New("received a non-successful HTTP response")
	}

	out, err := os.Create(filepath.Join(directory, premainName))
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	fmt.Printf("Successfully downloaded %s.\n", premainName)

	return nil
}

/*
	Perform the manifest modification.
	For existing entries: Run a RegEx search, replace the line.
	For new entries: Append to the end of the file.
	NOTE: This only works for flat-mapped TOML configs.
	These seem to be usually used for Graphene manifests.
	However, TOML is quite flexible, and there are no TOML parsers out there which are style & comments preserving
	So, if we do not have a flat-mapped config, this will fail at some point.
*/
func appendAndReplace(changeDiffs []diff, manifestContent []byte) ([]byte, error) {
	newManifestContent := manifestContent

	var firstAdditionDone bool
	for _, value := range changeDiffs {
		if value.alreadyExists {
			// If a value was previously existing, we replace the existing entry
			key := strings.Split(value.manifestEntry, " =")
			regexKey := strings.ReplaceAll(key[0], ".", "\\.")
			regex := regexp.MustCompile("(?m)^" + regexKey + "\\s?=.*$")
			// Check if we actually found the entry we searched for. If not, we might be dealing with a TOML file we cannot handle correctly without a full parser.
			regexMatches := regex.FindAll(newManifestContent, -1)
			if regexMatches == nil {
				color.Red("ERROR: Cannot find specified entry. Your Graphene config might not be flat-mapped.")
				color.Red("Marblerun can only automatically modify manifests using a flat hierarchy, as otherwise we would lose all styling & comments.")
				color.Red("To continue, please manually perform the changes printed above in your Graphene manifest.")
				return nil, errors.New("failed to detect position of config entry")
			} else if len(regexMatches) > 1 {
				color.Red("ERROR: Found multiple potential matches for automatic value substitution.")
				color.Red("Is the configuration valid (no multiple declarations)?")
				return nil, errors.New("found multiple matches for a single entry")
			}
			// But if everything went as expected, replace the entry
			newManifestContent = regex.ReplaceAll(newManifestContent, []byte(value.manifestEntry))
		} else {
			// If a value was not defined previously, we append the new entries down below
			if !firstAdditionDone {
				appendToFile := commentMarblerunAdditions
				newManifestContent = append(newManifestContent, []byte(appendToFile)...)
				firstAdditionDone = true
			}
			appendToFile := value.manifestEntry + "\n"
			newManifestContent = append(newManifestContent, []byte(appendToFile)...)
		}
	}

	return newManifestContent, nil
}
