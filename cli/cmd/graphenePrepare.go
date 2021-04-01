package cmd

import (
	"bufio"
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
	"github.com/pelletier/go-toml"
	"github.com/spf13/cobra"
)

// premainNameSpawn is the name of the premain executable used for the 'spawn' method
const premainNameSpawn = "premain-graphene"

// premainNamePreload is the name of the premain shared library used for the 'preload' method
const premainNamePreload = "premain-graphene.so"

// uuidName is the file name of a Marble's uuid
const uuidName = "uuid"

// longDescription is the help text shown for this command
const longDescription = `Modifies a Graphene manifest for use with Marblerun.

This command tries to automatically adjust the required parameters in an already existing Graphene manifest template, simplifying the migration of your existing Graphene application to Marblerun.
Please note that you still need to manually create a Marblerun manifest.

The first parameter of this command is either 'spawn' or 'preload'.

'spawn': Replace the entrypoint of your application with Marblerun's premain. Dedicates argv provisioning to Marblerun's manifest, but takes longer to load.

'preload': Loads Marblerun's premain as a shared library via LD_PRELOAD and keeps your original entrypoint intact.
This feature delegates argv provisioning to Graphene, making Marblerun unable to supply its own arguments via the Marblerun manifest, but keeps better compability with existing Graphene applications and leads to faster load times.

For more information about both modes, consult the documentation: https://www.marblerun.sh/docs/tasks/build-service-graphene/

The second parameter of this command is the path of the Graphene manifest template you want to modify.
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
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := args[0]
			fileName := args[1]

			mode = strings.ToLower(mode)
			if mode != "spawn" && mode != "preload" {
				return fmt.Errorf("unknown mode was chosen, aborting")
			}
			return addToGrapheneManifest(fileName, mode)
		},
		SilenceUsage: true,
	}

	return cmd
}

func addToGrapheneManifest(fileName string, mode string) error {
	// Check if file actually exists
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		return fmt.Errorf("file does not exist: %v", fileName)
	}

	// Read Graphene manifest and populate TOML tree
	fmt.Println("Reading file:", fileName)
	tree, err := toml.LoadFile(fileName)
	if err != nil {
		fmt.Println("\033[0;31mERROR: Cannot parse manifest. Have you selected the corrected file?\033[0m")
		return err
	}

	// Parse tree for changes and generate maps with original entries & changes
	original, changes, err := parseTreeForChanges(tree, mode)
	if err != nil {
		return err
	}

	// Calculate the differences, apply the changes
	return performChanges(calculateChanges(original, changes), fileName, mode)
}

func parseTreeForChanges(tree *toml.Tree, mode string) (map[string]interface{}, map[string]interface{}, error) {
	// Create two maps, one with original values, one with the values we want to add or modify
	original := make(map[string]interface{})
	changes := make(map[string]interface{})

	// The values we want to search in the original manifest
	original["libos.entrypoint"] = tree.Get("libos.entrypoint")
	original["loader.env.LD_PRELOAD"] = tree.Get("loader.env.LD_PRELOAD")
	original["loader.env.LD_LIBRARY_PATH"] = tree.Get("loader.env.LD_LIBRARY_PATH")
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
	if original["loader.env.LD_PRELOAD"] != nil {
		splittedPaths := strings.Split(original["loader.env.LD_PRELOAD"].(string), ":")
		for _, value := range splittedPaths {
			if strings.Contains(value, premainNamePreload) {
				return nil, nil, errors.New("manifest already contains Marblerun changes")
			}
		}
	}

	if original["libos.entrypoint"].(string) == premainNameSpawn || original["sgx.trusted_files.marblerun_premain"] != nil || original["sgx.allowed_files.marblerun_uuid"] != nil {
		return nil, nil, errors.New("manifest already contains Marblerun changes")
	}

	// Add changes to entry point depending on mode
	switch mode {
	case "spawn":
		// Set original endpoint as argv0. If one exists, keep the old one
		if original["loader.argv0_override"] == nil {
			fileEntry := strings.SplitAfter(original["libos.entrypoint"].(string), "file:")
			if len(fileEntry) == 2 {
				changes["loader.argv0_override"] = fileEntry[1]
			} else {
				return nil, nil, fmt.Errorf("cannot determine entrypoint for argv0 override correctly")
			}

			// Add premain-graphene executable as trusted file & entry point
			changes["libos.entrypoint"] = "file:" + premainNameSpawn
			changes["sgx.trusted_files.marblerun_premain"] = "file:" + premainNameSpawn
		}
	case "preload":
		// Add premain-graphene.so to LD_PRELOAD or append to existing LD_PRELOAD
		if original["loader.env.LD_PRELOAD"] == nil {
			changes["loader.env.LD_PRELOAD"] = "./" + premainNamePreload
		} else {
			changes["loader.env.LD_PRELOAD"] = original["loader.env.LD_PRELOAD"].(string) + ":./" + premainNamePreload
		}

		// Check if LD_LIBRARY_PATH contains /lib, add otherwise
		if original["loader.env.LD_LIBRARY_PATH"] == nil {
			changes["loader.env.LD_LIBRARY_PATH"] = "/lib"
		} else {
			splittedPaths := strings.Split(original["loader.env.LD_LIBRARY_PATH"].(string), ":")
			var foundLib bool
			for _, value := range splittedPaths {
				if value == "/lib" {
					foundLib = true
					break
				}
			}
			if !foundLib {
				changes["loader.env.LD_LIBRARY_PATH"] = original["loader.env.LD_LIBRARY_PATH"].(string) + ":/lib"
			}
		}

		// Add premain-graphene.so as trusted file
		changes["sgx.trusted_files.marblerun_premain"] = "file:" + premainNamePreload
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
	if original["sgx.enclave_size"] != nil {
		var v datasize.ByteSize
		v.UnmarshalText([]byte(original["sgx.enclave_size"].(string)))
		if v.GBytes() < 1.00 {
			changes["sgx.enclave_size"] = "1024M"
		}
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
			var diffLine string
			switch v := changedValue.(type) {
			case string:
				diffLine = fmt.Sprintf("%s = \"%v\"", index, v)
			default:
				diffLine = fmt.Sprintf("%s = %v", index, v)
			}

			// alreadyExisting = false means, the entry existed and was set to nil.
			// alreadyExisting = true means, the entry existed and was not set to nil.
			newDiff := diff{manifestEntry: diffLine}
			if originalValue != nil {
				newDiff.alreadyExists = true
			} else {
				newDiff.alreadyExists = false
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
func performChanges(changeDiffs []diff, fileName string, mode string) error {
	fmt.Println("\nMarblerun suggests the following changes to your Graphene manifest:")
	for _, entry := range changeDiffs {
		if entry.alreadyExists {
			fmt.Printf("\033[0;33m%s\033[0m\n", entry.manifestEntry)
		} else {
			fmt.Printf("\033[0;32m%s\033[0m\n", entry.manifestEntry)
		}
	}

	// Prompt user for confirmation
	fmt.Printf("\nDo you want to automatically apply the suggested changes [y/n]? ")
	reader := bufio.NewReader(os.Stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return err
	}

	response = strings.ToLower(strings.TrimSpace(response))

	if response != "y" && response != "yes" {
		fmt.Println("Aborting.")
		return nil
	}

	directory := filepath.Dir(fileName)
	// Download Marblerun premain for Graphene from GitHub
	if err := downloadPremain(directory, mode); err != nil {
		var fileName string
		if mode == "spawn" {
			fileName = premainNameSpawn
		} else if mode == "preload" {
			fileName = premainNamePreload
		}
		fmt.Printf("\033[0;31mERROR: Cannot download '%s' from GitHub. Please add the file manually.\033[0m", fileName)
	}

	// Read Graphene manifest as normal text file
	manifestContent, err := ioutil.ReadFile(fileName)
	if err != nil {
		return err
	}
	// Backup original manifest
	backupFileName := filepath.Base(fileName) + ".bak"
	fmt.Printf("Saving original manifest as %s...\n", backupFileName)
	if err := ioutil.WriteFile(filepath.Join(directory, backupFileName), manifestContent, 0644); err != nil {
		return err
	}

	// Perform modifications to manifest
	fileNameBase := filepath.Base(fileName)
	fmt.Printf("Applying changes to %s...\n", fileNameBase)
	manifestContent, err = appendAndReplace(changeDiffs, manifestContent)
	if err != nil {
		return err
	}

	// Write modified file to disk
	if err := ioutil.WriteFile(fileName, manifestContent, 0644); err != nil {
		return err
	}

	fmt.Println("\nDone! You should be good to go for Marblerun!")

	return nil
}

func downloadPremain(directory string, mode string) error {
	cleanVersion := "v" + strings.Split(Version, "-")[0]

	// Download premain-graphene as executable (spawn) or as shared library (preload), depending on user's choice
	var downloadName string
	if mode == "spawn" {
		downloadName = premainNameSpawn
	} else if mode == "preload" {
		downloadName = premainNamePreload
	} else {
		return errors.New("unknown premain mode, cannot download premain")
	}

	resp, err := http.Get(fmt.Sprintf("https://github.com/edgelesssys/marblerun/releases/download/%s/%s", cleanVersion, downloadName))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 && resp.StatusCode > 299 {
		return errors.New("received a non-successful HTTP response")
	}

	out, err := os.Create(filepath.Join(directory, downloadName))
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}

	fmt.Printf("Successfully downloaded %s.\n", downloadName)

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
			regex := regexp.MustCompile("\\b" + regexKey + "\\b.*")
			// Check if we actually found the entry we searched for. If not, we might be dealing with a TOML file we cannot handle correctly without a full parser.
			if regex.Find(newManifestContent) == nil {
				fmt.Println("\033[0;31mERROR: Cannot find specified entry. Your Graphene config might not be flat-mapped.")
				fmt.Println("Marblerun can only automatically modify manifests using a flat hierarchy, as otherwise we would lose all styling & comments.")
				fmt.Println("To continue, please manually perform the changes printed above in your Graphene manifest.\033[0m")
				return nil, errors.New("failed to detect position of config entry")
			}
			// But if everything went as expected, replace the entry
			newManifestContent = regex.ReplaceAll(newManifestContent, []byte(value.manifestEntry))
		} else {
			// If a value was not defined previously, we append the new entries down below
			if !firstAdditionDone {
				appendToFile := "\n# Marblerun -- auto generated configuration entries" + "\n"
				newManifestContent = append(newManifestContent, []byte(appendToFile)...)
				firstAdditionDone = true
			}
			appendToFile := value.manifestEntry + "\n"
			newManifestContent = append(newManifestContent, []byte(appendToFile)...)
		}
	}

	return newManifestContent, nil
}
