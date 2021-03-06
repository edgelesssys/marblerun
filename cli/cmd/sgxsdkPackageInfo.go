package cmd

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func newSGXSDKPackageInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sgxsdk-package-info",
		Short: "Prints the package signature properties of an SGX SDK binary",
		Long:  "Prints the package signature properties of an SGX SDK binary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			path := args[0]

			return decodeSigStruct(path)
		},
		SilenceUsage: true,
	}

	return cmd
}

func decodeSigStruct(path string) error {
	// Check if given filename is actually a directory
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	// If it is, we try to find out if it's an Occlum image directory
	var elfFile *elf.File
	var isOcclumInstance bool
	if isDirectory := stat.IsDir(); isDirectory {
		if elfFile, err = elf.Open(filepath.Join(path, "build/lib/libocclum-libos.signed.so")); err == nil {
			color.Green("Detected Occlum image.")
			isOcclumInstance = true
		} else if os.IsNotExist(err) {
			color.Red("ERROR: A directory was supplied, but it appears not to be an Occlum instance.")
			color.Red("Please either specify the SGX enclave binary directly, or the root of an Occlum instance.")
			return err
		}
	} else {
		elfFile, err = elf.Open(path)
	}
	if err != nil {
		return err
	}
	defer elfFile.Close()

	// SIGSTRUCT is stored in ELF section '.note.sgxmeta'
	sgxMetaSection := elfFile.Section(".note.sgxmeta")
	if sgxMetaSection == nil {
		return errors.New("could not find SGX metadata section (.note.sgxmeta) in given file")
	}

	sgxMetaData, err := sgxMetaSection.Data()
	if err != nil {
		return err
	}

	// Parse and retrieve values from SIGSTRUCT
	mrenclave, mrsigner, isvprodid, isvsvn, err := parseSigStruct(sgxMetaData)
	if err != nil {
		return nil
	}

	// Display the determined properties
	if isOcclumInstance {
		color.Cyan("PackageProperties for Occlum image at '%s':\n", path)
	} else {
		color.Cyan("PackageProperties for '%s':\n", path)
	}
	fmt.Printf("UniqueID (MRENCLAVE)      : %s\n", hex.EncodeToString(mrenclave))
	fmt.Printf("SignerID (MRSIGNER)       : %s\n", hex.EncodeToString(mrsigner[:]))
	fmt.Printf("ProductID (ISVPRODID)     : %d\n", binary.LittleEndian.Uint16(isvprodid))
	fmt.Printf("SecurityVersion (ISVSVN)  : %d\n", binary.LittleEndian.Uint16(isvsvn))

	return nil
}

func parseSigStruct(sgxMetaData []byte) ([]byte, []byte, []byte, []byte, error) {
	/*
	 * From the "Intel(r) 64 and IA-32 Architectures Software Developer
	 * Manual, Volume 3: System Programming Guide", Chapter 38, Section 13,
	 * Table 38-19 "Layout of Enclave Signature Structure (SIGSTRUCT)"
	 */
	sigStructHeader := []byte{0x06, 0x00, 0x00, 0x00, 0xe1, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00}

	sigStructIndex := bytes.Index(sgxMetaData, sigStructHeader)
	if sigStructIndex == -1 {
		return nil, nil, nil, nil, errors.New("could not find SIGSTRUCT header in given file")
	}

	// The Intel Software Developer Manual specifies SIGSTRUCT entries up to 1808 bytes.
	// We use this as a cutoff for our sigStruct slice.
	if len(sgxMetaData) <= sigStructIndex+1808 {
		return nil, nil, nil, nil, errors.New("SGX metadata/SIGSTRUCT appears to be too small")
	}

	sigStruct := sgxMetaData[sigStructIndex : sigStructIndex+1808]

	// SIGSTRUCT has two headers. Let's check against the second one, too.
	// We only use the second one to verify that we actually work on the correct struct.
	sigStructHeader2 := []byte{0x01, 0x01, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x60, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}
	sigStructHeader2Index := bytes.Index(sigStruct, sigStructHeader2)
	if sigStructHeader2Index == -1 {
		return nil, nil, nil, nil, errors.New("found first SIGSTRUCT header, but cannot find second one")
	}

	// Get MRENCLAVE (UniqueID), ISVPRODID (ProductID) and ISVSVN (SecurityVersion) directly from SIGSTRUCT
	// Get Modulus so we can calculate MRSIGNER (= SHA256 hash of modulus)
	modulus := sigStruct[128:512]
	mrenclave := sigStruct[960:992]
	isvprodid := sigStruct[1024:1026]
	isvsvn := sigStruct[1026:1028]

	// Calculate MRSIGNER, which is the SHA-256 hash of the modulus stored in SIGSTRUCT
	mrsigner := sha256.Sum256(modulus)

	return mrenclave, mrsigner[:], isvprodid, isvsvn, nil
}
