package server

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/edgelesssys/coordinator/coordinator/core"
	"github.com/edgelesssys/coordinator/coordinator/rpc"
	"github.com/gorilla/handlers"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type certQuoteResp struct {
	Cert  string
	Quote []byte
}
type statusResp struct {
	Status string
}
type manifestSignatureResp struct {
	ManifestSignature []byte
}

// RunMarbleServer starts a gRPC with the given Coordinator core.
// `address` is the desired TCP address like "localhost:0".
// The effective TCP address is returned via `addrChan`.
func RunMarbleServer(core *core.Core, addr string, addrChan chan string, errChan chan error) {
	cert, err := core.GetTLSCertificate()
	if err != nil {
		errChan <- err
		return
	}
	tlsConfig := tls.Config{
		Certificates: []tls.Certificate{*cert},
		// NOTE: we'll verify the cert later using the given quote
		ClientAuth: tls.RequireAnyClientCert,
	}
	creds := credentials.NewTLS(&tlsConfig)
	grpcServer := grpc.NewServer(grpc.Creds(creds), withServerUnaryInterceptor(core))
	rpc.RegisterMarbleServer(grpcServer, core)
	socket, err := net.Listen("tcp", addr)
	if err != nil {
		errChan <- err
		return
	}
	addrChan <- socket.Addr().String()
	err = grpcServer.Serve(socket)
	if err != nil {
		errChan <- err
	}
}

func withServerUnaryInterceptor(c *core.Core) grpc.ServerOption {
	mai := &core.MarbleAPIInterceptor{Core: c}
	return grpc.UnaryInterceptor(mai.UnaryServerInterceptor)
}

// CreateServeMux creates a mux that serves the client API. provisionally
func CreateServeMux(cc core.ClientCore) *http.ServeMux {
	mux := http.NewServeMux()

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			status, err := cc.GetStatus(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			strct := statusResp{status}
			jsn, err := json.Marshal(strct)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(jsn)
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/manifest", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			signature := cc.GetManifestSignature(r.Context())
			strct := manifestSignatureResp{signature}
			jsn, err := json.Marshal(strct)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			io.WriteString(w, string(jsn))
		case http.MethodPost:
			manifest, err := ioutil.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			if err := cc.SetManifest(r.Context(), manifest); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})
	mux.HandleFunc("/quote", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			cert, quote, err := cc.GetCertQuote(r.Context())
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			strct := certQuoteResp{cert, quote}
			jsn, err := json.Marshal(strct)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			w.Write(jsn)
		default:
			http.Error(w, "", http.StatusMethodNotAllowed)
		}
	})

	return mux
}

// RunClientServer runs a HTTP server serving mux. provisionally
func RunClientServer(mux *http.ServeMux, address string, tlsConfig *tls.Config) {
	loggedRouter := handlers.LoggingHandler(os.Stdout, mux)
	server := http.Server{
		Addr:      address,
		Handler:   loggedRouter,
		TLSConfig: tlsConfig,
	}
	log.Println("starting https server at ", address)
	log.Println(server.ListenAndServeTLS("", ""))
}

type malformedRequest struct {
	status int
	msg    string
}

func (mr *malformedRequest) Error() string {
	return mr.msg
}
