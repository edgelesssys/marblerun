package premain

import (
	"crypto/x509"
	"errors"
	"os"
	"testing"

	"github.com/edgelesssys/marblerun/coordinator/quote"
	"github.com/edgelesssys/marblerun/coordinator/rpc"
	"github.com/edgelesssys/marblerun/marble/config"
	"github.com/google/uuid"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/credentials"
)

func TestPreMain(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	// The test will modify os.Args, restore it afterwards.
	argsBackup := os.Args
	defer func() { os.Args = argsBackup }()

	// These are returned by the activate mock function and will be set to different values to test different scenarios.
	var parameters *rpc.Parameters
	var activateError error

	// Mocks the coordinator.
	activate := func(req *rpc.ActivationReq, coordAddr string, tlsCredentials credentials.TransportCredentials) (*rpc.Parameters, error) {
		assert.Equal("addr", coordAddr)
		assert.NotNil(tlsCredentials)
		assert.Equal("type", req.MarbleType)
		assert.NotEmpty(req.Quote)
		_, err := uuid.Parse(req.UUID)
		assert.NoError(err)

		csr, err := x509.ParseCertificateRequest(req.CSR)
		require.NoError(err)
		assert.NoError(csr.CheckSignature())
		assert.Equal([]string{"dns1", "dns2"}, csr.DNSNames)

		return parameters, activateError
	}

	issuer := quote.NewMockIssuer()

	require.NoError(os.Setenv(config.CoordinatorAddr, "addr"))
	require.NoError(os.Setenv(config.Type, "type"))
	require.NoError(os.Setenv(config.UUIDFile, "uuidfile"))
	require.NoError(os.Setenv(config.DNSNames, "dns1,dns2"))

	// Actual tests follow.

	{
		parameters = &rpc.Parameters{}
		activateError = nil

		hostfs := afero.NewMemMapFs()
		enclavefs := afero.NewMemMapFs()
		require.NoError(preMain(issuer, activate, hostfs, enclavefs))

		savedUUID, err := afero.ReadFile(hostfs, "uuidfile")
		assert.NoError(err)
		assert.Len(savedUUID, len(uuid.UUID{}))

		assert.Equal([]string{"./marble"}, os.Args)
	}
	{
		parameters = &rpc.Parameters{}
		activateError = errors.New("test")

		os.Args = []string{"not modified"}

		hostfs := afero.NewMemMapFs()
		enclavefs := afero.NewMemMapFs()
		require.Error(preMain(issuer, activate, hostfs, enclavefs))

		_, err := afero.ReadFile(hostfs, "uuidfile")
		assert.Error(err)

		assert.Equal([]string{"not modified"}, os.Args)
	}
	{
		parameters = &rpc.Parameters{
			Files: map[string]string{
				"path1": "data1",
				"path2": "data2",
			},
			Env: map[string]string{
				"EDG_TEST_1": "env1",
				"EDG_TEST_2": "env2",
			},
			Argv: []string{"arg0", "arg1"},
		}
		activateError = nil

		require.NoError(os.Unsetenv("EDG_TEST_1"))
		require.NoError(os.Unsetenv("EDG_TEST_2"))

		hostfs := afero.NewMemMapFs()
		enclavefs := afero.NewMemMapFs()
		require.NoError(preMain(issuer, activate, hostfs, enclavefs))

		savedUUID, err := afero.ReadFile(hostfs, "uuidfile")
		assert.NoError(err)
		assert.Len(savedUUID, len(uuid.UUID{}))

		data, err := afero.ReadFile(enclavefs, "path1")
		assert.NoError(err)
		assert.Equal([]byte("data1"), data)
		data, err = afero.ReadFile(enclavefs, "path2")
		assert.NoError(err)
		assert.Equal([]byte("data2"), data)

		assert.Equal("env1", os.Getenv("EDG_TEST_1"))
		assert.Equal("env2", os.Getenv("EDG_TEST_2"))

		assert.Equal([]string{"arg0", "arg1"}, os.Args)
	}
	{
		// parameters as before
		activateError = errors.New("test")

		os.Args = []string{"not modified"}
		require.NoError(os.Unsetenv("EDG_TEST_1"))
		require.NoError(os.Unsetenv("EDG_TEST_2"))

		hostfs := afero.NewMemMapFs()
		enclavefs := afero.NewMemMapFs()
		require.Error(preMain(issuer, activate, hostfs, enclavefs))

		_, err := afero.ReadFile(hostfs, "uuidfile")
		assert.Error(err)

		_, err = afero.ReadFile(enclavefs, "path1")
		assert.Error(err)
		_, err = afero.ReadFile(enclavefs, "path2")
		assert.Error(err)

		assert.Equal("", os.Getenv("EDG_TEST_1"))
		assert.Equal("", os.Getenv("EDG_TEST_2"))

		assert.Equal([]string{"not modified"}, os.Args)
	}
}
