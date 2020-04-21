package coordinator

import (
	"testing"

	"golang.org/x/net/context"

	"github.com/stretchr/testify/assert"
)

func TestServer(t *testing.T) {
	var s *Server
	var err error

	t.Run("create server", func(t *testing.T) {
		s, err = NewServer("edgeless")
		assert.NotNil(t, s)
		assert.Nil(t, err)
		assert.Equal(t, s.state, acceptingManifest)
		assert.Equal(t, s.cert.Subject.Organization, []string{"edgeless"})
		assert.Equal(t, s.cert.Subject.CommonName, coordinatorName)
	})

	// t.Run("attempt to activate node prematurely", func(t *testing.T) {
	// 	s.Activate(context.TODO(), )
	// })

	const manifest string = `{
		"Packages": {
			"tikv": {
				"MREnclave": [1,2,3,4],
				"ISVProdID": 99,
				"MinISVSVN": 2
			},
			"tidb": {
				"MRSigner": [5,6,7,8,9,10],
				"ISVProdID": 44,
				"MinISVSVN": 3,
				"Attributes": [1,1,1,1]
			}
		},
		"Attestation": {
			"MinCPUSVN": [3,3,3],
			"RootCAs": {
				"Intel": [4,4,4],
				"Azure": [5,5,5]
			}
		},
		"Nodes": {
			"tikv_first": {
				"Package": "tikv",
				"MaxActivations": 1,
				"Parameters": {
					"Files": {
						"/abc/defg.txt": [7,7,7],
						"/ghi/jkl.mno": [8,8,8]
					},
					"Env": {
						"IS_FIRST": "true"
					},
					"Argv": [
						"--first",
						"serve"
					]
				}
			},
			"tikv_other": {
				"Package": "tikv",
				"Parameters": {
					"Argv": [
						"serve"
					]
				}
			},
			"tidb": {
				"Package": "tidb"
			}
		},
		"Clients": {
			"owner": [9,9,9]
		}
		}`

	t.Run("attempt to set broken manifest", func(t *testing.T) {
		assert.NotNil(t, s.SetManifest(context.TODO(), []byte(manifest)[:len(manifest)-1]))
	})

	t.Run("set manifest", func(t *testing.T) {
		assert.Nil(t, s.SetManifest(context.TODO(), []byte(manifest)))
	})

	// firstTikv := rpc.ActivationReq{
	// 	Quote : {1,2,3,4},

	// }

	// t.Run("activate first tikv", func(t *testing.T) {

	// })
}
