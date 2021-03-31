package cmd

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/c2h5oh/datasize"
	"github.com/pelletier/go-toml"
	"github.com/spf13/cobra"
)

type diff struct {
	manifestEntry   string
	alreadyExisting bool
}

func newGraphenePrepareCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graphene-prepare",
		Short: "Modifies a Graphene manifest for use with Marblerun",
		Long:  "Modifies a Graphene manifest for use with Marblerun",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			mode := args[0]
			fileName := args[1]

			fmt.Println("Marblerun 🤝 Graphene")
			fmt.Printf("Arg 1: %s, Arg 2: %s\n", mode, fileName)

			switch strings.ToLower(mode) {
			case "spawn":
				return addSpawnToGrapheneManifest(fileName)
			case "preload":
				return addPreloadToGrapheneManifest(fileName)
			default:
				return fmt.Errorf("unknown mode was chosen, aborting")
			}
		},
		SilenceUsage: true,
	}

	return cmd
}

func addSpawnToGrapheneManifest(fileName string) error {
	// Read Graphene manifest and populate TOML tree
	fmt.Println("Reading file:", fileName)
	tree, err := toml.LoadFile(fileName)
	if err != nil {
		return err
	}

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
		return errors.New("cannot find libos.entrypoint")
	}

	// If Marblerun already touched the manifest, abort.
	if original["libos.entrypoint"].(string) == "premain-graphene" || original["sgx.trusted_files.marblerun_premain"] != nil || original["sgx.allowed_files.marblerun_uuid"] != nil {
		return errors.New("manifest already contains Marblerun changes")
	}

	// Set original endpoint as argv0. If one exists, keep the old one
	if original["loader.argv0_override"] == nil {
		fileEntry := strings.SplitAfter(original["libos.entrypoint"].(string), "file:")
		if len(fileEntry) == 2 {
			changes["loader.argv0_override"] = fileEntry[1]
		} else {
			return fmt.Errorf("cannot determine entrypoint for argv0 override correctly")
		}
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

	// Add Marblerun entries to manifest
	changes["libos.entrypoint"] = "file:premain-graphene"
	changes["sgx.trusted_files.marblerun_premain"] = "file:premain-graphene"
	changes["sgx.allowed_files.marblerun_uuid"] = "file:uuid"

	return performChanges(calculateChanges(original, changes))
}

func addPreloadToGrapheneManifest(fileName string) error {
	return nil
}

// calculateChanges takes two maps with TOML indices and values as input and calculates the difference between them
func calculateChanges(original map[string]interface{}, updates map[string]interface{}) []diff {
	var changeDiffs []diff
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

			newDiff := diff{manifestEntry: diffLine}
			if originalValue != nil {
				newDiff.alreadyExisting = true
			} else {
				newDiff.alreadyExisting = false
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
func performChanges(changeDiffs []diff) error {
	fmt.Println("\nMarblerun suggests the following changes to your Graphene manifest:")
	for _, entry := range changeDiffs {
		if entry.alreadyExisting {
			fmt.Printf("\033[0;33m%s\033[0m\n", entry.manifestEntry)
		} else {
			fmt.Printf("\033[0;32m%s\033[0m\n", entry.manifestEntry)
		}
	}

	// Prompt user for confirmation
	fmt.Printf("Do you want to automatically apply the suggested changes [y/n]? ")
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

	return nil
}
