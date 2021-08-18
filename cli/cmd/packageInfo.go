package cmd

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func newPackageInfoCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "package-info",
		Short: "Prints the package signature properties of an enclave",
		Long:  "Prints the package signature properties of an enclave",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			enclaveType := args[0]
			path := args[1]

			enclaveType = strings.ToLower(enclaveType)

			if enclaveType == "oe" || enclaveType == "openenclave" || enclaveType == "edgeless" || enclaveType == "ego" {
				return decodeOpenEnclaveSigStruct(path)
			} else if enclaveType == "graphene" {
				return decodeGrapheneSigStruct(path)
			} else if enclaveType == "occlum" || enclaveType == "sgxsdk" {
				return decodeSGXSDKSigStruct(path)
			}

			return errors.New("unsupported enclave type")
		},
		SilenceUsage: true,
	}

	return cmd
}

func decodeSGXSDKSigStruct(path string) error {
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

	printPackageProperties(mrenclave, mrsigner, isvprodid, isvsvn)

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

func decodeGrapheneSigStruct(path string) error {
	// Check if given filename is actually a directory
	stat, err := os.Stat(path)
	if err != nil {
		return err
	}

	// Check if directory contains a file ending in .sig
	var sigFile string
	var isDirectory bool
	if isDirectory = stat.IsDir(); isDirectory {
		fsInfo, err := ioutil.ReadDir(path)
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
				color.Green("Detected Graphene instance.")
			}
		}
		if !foundSigFile {
			color.Red("ERROR: A directory was supplied, but a Graphene SGX signature file cannot be found.")
			color.Red("Please either specify a correct directory, or point to the Graphene SGX .sig file directly.")
			return errors.New("did not find Graphene .sig file in directory")
		}
		sigFile = filepath.Join(path, sigFile)
	} else {
		sigFile = path
	}

	// Try to load the file
	sigContent, err := ioutil.ReadFile(sigFile)
	if err != nil {
		return err
	}

	mrenclave, mrsigner, isvprodid, isvsvn, err := parseSigStruct(sigContent)
	if err != nil {
		return err
	}

	if isDirectory {
		color.Cyan("PackageProperties for Graphene instance at '%s':\n", path)
	} else {
		color.Cyan("PackageProperties for '%s':\n", path)
	}

	printPackageProperties(mrenclave, mrsigner[:], isvprodid, isvsvn)

	return nil
}

func printPackageProperties(mrenclave []byte, mrsigner []byte, isvprodid []byte, isvsvn []byte) {
	fmt.Printf("UniqueID (MRENCLAVE)      : %s\n", hex.EncodeToString(mrenclave))
	fmt.Printf("SignerID (MRSIGNER)       : %s\n", hex.EncodeToString(mrsigner[:]))
	fmt.Printf("ProductID (ISVPRODID)     : %d\n", binary.LittleEndian.Uint16(isvprodid))
	fmt.Printf("SecurityVersion (ISVSVN)  : %d\n", binary.LittleEndian.Uint16(isvsvn))
}

func decodeOpenEnclaveSigStruct(path string) error {
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
	color.Cyan("PackageProperties for '%s':\n", path)
	printPackageProperties(mrenclave, mrsigner[:], isvprodid, isvsvn)

	return nil
}
