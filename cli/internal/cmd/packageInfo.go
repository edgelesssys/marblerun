// Copyright (c) Edgeless Systems GmbH.
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package cmd

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

func NewPackageInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package-info",
		Short: "Print the package signature properties of an enclave",
		Long:  "Print the package signature properties of an enclave",
		Args:  cobra.ExactArgs(1),
		RunE:  runPackageInfo,
	}

	return cmd
}

func runPackageInfo(cmd *cobra.Command, args []string) error {
	path := args[0]

	// Check if given filename is actually a directory
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}
	isDirectory := stat.IsDir()

	// For Open Enclave / Edgeless RT / EGo, we require to directly point to the signed enclave binary, as these do not have a specific directory structure
	var errOpenEnclave error
	if !isDirectory {
		errOpenEnclave = decodeOpenEnclaveSigStruct(cmd.OutOrStdout(), path)
		if errOpenEnclave == nil {
			return nil
		}
	}

	// In every other case, try to guess if it's a directory, or expect a specific file to be pointed to
	errGramine := decodeGramineSigStruct(cmd.OutOrStdout(), path, isDirectory)
	if errGramine == nil {
		return nil
	}
	errOcclum := decodeSGXSDKSigStruct(cmd.OutOrStdout(), path, isDirectory) // Either Occlum or SGX SDK
	if errOcclum == nil {
		return nil
	}

	cmd.PrintErrln("ERROR: Failed to automatically determine SGX package signature properties.")
	if isDirectory {
		cmd.PrintErrln("A directory was supplied, but it appears not to be a Gramine or Occlum instance.")
		cmd.PrintErrln("Please either specify the .sig file (Gramine) or SGX enclave binary (Occlum / SGX SDK) directly, or the root directory of an Gramine or Occlum instance.")
	}
	cmd.Println()

	// Output exact errors for each detection method to user
	cmd.PrintErrf("Open Enclave detection error: %s\n", errOpenEnclave)
	cmd.PrintErrf("Error - Gramine: %s\n", errGramine)
	cmd.PrintErrf("Error - Occlum / SGX SDK: %s\n", errOcclum)
	return errors.New("unable to determine enclave properties")
}

func decodeSGXSDKSigStruct(out io.Writer, path string, isDirectory bool) error {
	// If the path is a directory, we try to find out if it's an Occlum image directory
	var elfFile *elf.File
	var isOcclumInstance bool
	var err error
	if isDirectory {
		if elfFile, err = elf.Open(filepath.Join(path, "build/lib/libocclum-libos.signed.so")); err == nil {
			fmt.Fprintln(out, "Detected Occlum image.")
			isOcclumInstance = true
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
		fmt.Fprintf(out, "PackageProperties for Occlum image at '%s':\n", path)
	} else {
		fmt.Fprintf(out, "PackageProperties for '%s':\n", path)
	}

	printPackageProperties(out, mrenclave, mrsigner, isvprodid, isvsvn)

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
	const sigStructLen = 1808
	if len(sgxMetaData) < sigStructIndex+sigStructLen {
		return nil, nil, nil, nil, errors.New("SGX metadata/SIGSTRUCT appears to be too small")
	}

	sigStruct := sgxMetaData[sigStructIndex : sigStructIndex+sigStructLen]

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

func decodeGramineSigStruct(out io.Writer, path string, isDirectory bool) error {
	// Check if directory contains a file ending in .sig
	var sigFile string
	if isDirectory {
		fsInfo, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		foundSigFile := false
		for _, entry := range fsInfo {
			if filepath.Ext(entry.Name()) == ".sig" {
				if foundSigFile {
					return errors.New("found multiple .sig files")
				}
				foundSigFile = true
				sigFile = entry.Name()
				fmt.Fprintln(out, "Detected Gramine instance.")
			}
		}
		if !foundSigFile {
			return errors.New("did not find Gramine .sig file in directory")
		}
		sigFile = filepath.Join(path, sigFile)
	} else {
		sigFile = path
	}

	// Try to load the file
	sigContent, err := os.ReadFile(sigFile)
	if err != nil {
		return err
	}

	mrenclave, mrsigner, isvprodid, isvsvn, err := parseSigStruct(sigContent)
	if err != nil {
		return err
	}

	if isDirectory {
		fmt.Fprintf(out, "PackageProperties for Gramine instance at '%s':\n", path)
	} else {
		fmt.Fprintf(out, "PackageProperties for '%s':\n", path)
	}

	printPackageProperties(out, mrenclave, mrsigner[:], isvprodid, isvsvn)

	return nil
}

func printPackageProperties(out io.Writer, mrenclave []byte, mrsigner []byte, isvprodid []byte, isvsvn []byte) {
	fmt.Fprintf(out, "UniqueID (MRENCLAVE)      : %s\n", hex.EncodeToString(mrenclave))
	fmt.Fprintf(out, "SignerID (MRSIGNER)       : %s\n", hex.EncodeToString(mrsigner[:]))
	fmt.Fprintf(out, "ProductID (ISVPRODID)     : %d\n", binary.LittleEndian.Uint16(isvprodid))
	fmt.Fprintf(out, "SecurityVersion (ISVSVN)  : %d\n", binary.LittleEndian.Uint16(isvsvn))
}

func decodeOpenEnclaveSigStruct(out io.Writer, path string) error {
	// Open ELF file
	elfFile, err := elf.Open(path)
	if err != nil {
		return err
	}
	defer elfFile.Close()

	// Search for .oeinfo section containing which should contain SGX SIGSTRUCT section
	oeInfo := elfFile.Section(".oeinfo")
	if oeInfo == nil {
		return errors.New("could not find .oeinfo ELF section in binary")
	}

	// Load binary data of .oeinfo section
	oeInfoData, err := oeInfo.Data()
	if err != nil {
		return err
	}

	// Pass whole .oeinfo section to the SIGSTRUCT parser and let it search for the SIGSTRUCT section
	mrenclave, mrsigner, isvprodid, isvsvn, err := parseSigStruct(oeInfoData)
	if err != nil {
		return err
	}

	// Print PackageProperties of detected SIGSTRUCT
	fmt.Fprintf(out, "PackageProperties for '%s':\n", path)
	printPackageProperties(out, mrenclave, mrsigner[:], isvprodid, isvsvn)

	return nil
}
