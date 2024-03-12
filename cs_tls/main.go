package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/net/http2"
)

var (
	socketPath    = "/run/container_launcher/teeserver.sock"
	tokenEndpoint = "http://localhost/v1/token"
	contentType   = "application/json"
)

func getCustomToken(nonce string) {
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		},
	}

	// token IPC endpoint
	url := tokenEndpoint
	body := fmt.Sprintf(`{
		"audience": "https://sts.amazon.com",
		"nonces": [%s]
	}`, nonce)

	resp, err := httpClient.Post(url, contentType, strings.NewReader(body))
	if err != nil {
		panic(err)
	}
	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	fmt.Println(string(tokenbytes))

	mapClaims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(tokenbytes), mapClaims)
	if err != nil {
		panic(err)
	}
	claimsString, err := json.MarshalIndent(mapClaims, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(claimsString))
}

func doNothing(writer http.ResponseWriter, r *http.Request) {
	ekm, err := r.TLS.ExportKeyingMaterial("testing_nonce", nil, 32)
	if err != nil {
		fmt.Println("failed to get EKM from inbound http request")
		panic(err)
	}

	sha := sha256.New()
	sha.Write(ekm)
	hash := sha.Sum(nil)

	getCustomToken(string(hash))
}

// Handler creates a multiplexer for the server.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/tlstest", doNothing)
	return mux
}

func main() {
	var err error
	tlsConfig := &tls.Config{}

	server := &http.Server{
		Addr:      ":8081",
		Handler:   Handler(),
		TLSConfig: tlsConfig,
	}
	http2.ConfigureServer(server, &http2.Server{})
	fmt.Println("Starting Server..")
	err = server.ListenAndServeTLS("./server.crt", "./server.key")
	fmt.Printf("Unable to start Server %v", err)
}
