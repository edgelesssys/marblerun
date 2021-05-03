package cmd

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/c2h5oh/datasize"
	"github.com/jarcoal/httpmock"
	"github.com/pelletier/go-toml"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const someManifest = `
libos.entrypoint = "file:myapplication"
sgx.remote_attestation = 0
# Some comment here in between
# This should not match: sgx.enclave_size - 2
# This should also not match: sgx.enclave_size = 24M
sgx.enclave_size = "128M"
`

func TestCalculateChanges(t *testing.T) {
	assert := assert.New(t)

	originalMap := make(map[string]interface{})
	changedMap := make(map[string]interface{})

	originalMap["someString"] = "test" // should be in diffs
	originalMap["someNilValue"] = nil  // should be in diffs
	originalMap["someInt"] = 4         // should not be in diffs

	changedMap["someString"] = "This is a test."        // should be in diffs
	changedMap["someNilValue"] = true                   // should be in diffs
	changedMap["someNewEntry"] = "This is a new entry." // should not be in diffs

	diffs := calculateChanges(originalMap, changedMap)

	// NOTE: diffs only should contain changes which were at least defined on the original map
	// Values which were undefined before should not be in here
	for _, value := range diffs {
		indexString := strings.Split(value.manifestEntry, " =")
		_, ok := originalMap[indexString[0]]
		assert.True(ok, "Diffs contains entries which were not defined in the original map initially")
	}

	// Check if we got TOML style output
	// And check if diffs array was sorted correctly (is supposed to be sorted alphabetically)
	assert.Len(diffs, 2, "diffs contains unexpected amount of entries")
	assert.Equal(diffs[0].manifestEntry, "someNilValue = true")
	assert.Equal(diffs[1].manifestEntry, "someString = \"This is a test.\"")
}

func TestParseTreeForChanges(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	tree, err := toml.Load(someManifest)
	require.NoError(err)

	// Checking all possible combinations will result in tremendous effort...
	// So for this, we check if we at least changed the entry point and the memory/thread requirements for the Go runtime
	original, changes, err := parseTreeForChanges(tree)
	require.NoError(err)
	assert.NotEmpty(original)
	assert.NotEmpty(changes)

	// Verify minimum changes
	var v datasize.ByteSize

	assert.Equal("file:"+premainName, changes["libos.entrypoint"])
	assert.GreaterOrEqual(changes["sgx.thread_num"], 16)
	require.NoError(v.UnmarshalText([]byte(changes["sgx.enclave_size"].(string))))
	assert.GreaterOrEqual(v.GBytes(), 1.00)
}

func TestAppendAndReplace(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Parse hardcoded test manifest
	tomlTree, err := toml.Load(someManifest)
	require.NoError(err)

	// Get values from hardcoded test manifest
	original := make(map[string]interface{})
	changes := make(map[string]interface{})
	original["sgx.remote_attestation"] = tomlTree.Get("sgx.remote_attestation")
	original["sgx.enclave_size"] = tomlTree.Get("sgx.enclave_size")
	original["sgx.thread_num"] = tomlTree.Get("sgx.thread_num")

	// Set some changes we want to perform
	changes["sgx.remote_attestation"] = 1
	changes["sgx.enclave_size"] = "1024M"
	changes["sgx.thread_num"] = 16

	// Calculate the differences
	diffs := calculateChanges(original, changes)

	// Perform the modification
	someNewManifest, err := appendAndReplace(diffs, []byte(someManifest))
	assert.NoError(err)
	assert.NotEqualValues(someManifest, someNewManifest)

	// Check if it's still valid TOML & if changes were applied correctly
	newTomlTree, err := toml.Load(string(someNewManifest))
	assert.NoError(err)
	newRemoteAttestation := newTomlTree.Get("sgx.remote_attestation")
	assert.EqualValues(1, newRemoteAttestation.(int64))
	newEnclaveSize := newTomlTree.Get("sgx.enclave_size")
	assert.EqualValues("1024M", newEnclaveSize.(string))
	newThreadNum := newTomlTree.Get("sgx.thread_num")
	assert.EqualValues(16, newThreadNum.(int64))
}

func TestDownloadPremain(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// Use HTTP mock for external download
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()
	testContent := []byte("this is obviously not a binary, but we gotta test this anyway!")

	// We don't want to hardcode the version, so let's use a regexp match here
	httpmock.RegisterResponder("GET", `=~^https://github\.com/edgelesssys/marblerun/releases/download/v[0-9\.]*/premain-graphene`,
		httpmock.NewBytesResponder(200, testContent))

	// Create tempdir for downloads
	tempDir, err := ioutil.TempDir("", "")
	require.NoError(err)
	defer os.RemoveAll(tempDir)

	// Try to download premain
	assert.NoError(downloadPremain(tempDir))
	content, err := ioutil.ReadFile(filepath.Join(tempDir, premainName))
	assert.NoError(err)
	assert.Equal(testContent, content)

	// We should have one download here
	info := httpmock.GetCallCountInfo()
	assert.Equal(1, info[`GET =~^https://github\.com/edgelesssys/marblerun/releases/download/v[0-9\.]*/premain-graphene`])
}
