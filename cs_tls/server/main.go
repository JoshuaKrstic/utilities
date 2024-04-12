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

	"github.com/gorilla/websocket"
)

var (
	socketPath    = "/run/container_launcher/teeserver.sock"
	tokenEndpoint = "http://localhost/v1/token"
	contentType   = "application/json"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func GetOutboundIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	return localAddr.IP
}

func getCustomToken(nonce string) ([]byte, error) {
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
		return nil, err
	}
	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	fmt.Println(string(tokenbytes))

	mapClaims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(tokenbytes), mapClaims)
	if err != nil {
		return nil, err
	}
	claimsString, err := json.MarshalIndent(mapClaims, "", "  ")
	if err != nil {
		return nil, err
	}

	fmt.Printf("fetched token from the Attestation Service: %v\n", string(claimsString))
	return tokenbytes, nil
}

func handleConnectionRequest(w http.ResponseWriter, r *http.Request) {
	fmt.Println("")

	// Upgrade HTTP Connection to a websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("failed to upgrade connection to a websocket with err: %v\n", err)
		return
	}
	defer conn.Close()

	// Get EKM
	ekm, err := r.TLS.ExportKeyingMaterial("testing_nonce", nil, 32)
	if err != nil {
		fmt.Println("failed to get EKM from inbound http request")
		return
	}

	sha := sha256.New()
	sha.Write(ekm)
	hash := sha.Sum(nil)

	// Request token with TLS EKM hashed and return to requestor
	token, err := getCustomToken(string(hash))
	if err != nil {
		fmt.Printf("failed to get custom token from token endpoint: %v", err)
		return
	}

	conn.WriteMessage(1, token)

	for {
		messageType, content, err := conn.ReadMessage()
		if err != nil {
			fmt.Printf("failed to read message from the connection: %v\n", err)
			break
		}

		if messageType == 0 {
			fmt.Println("Received EOL message type")
			conn.WriteMessage(0, []byte("bye"))
			break
		}

		fmt.Printf("Receieved content from other side, %v\n", content)

		err = conn.WriteMessage(messageType, []byte("ok"))
		if err != nil {
			fmt.Printf("failed to send ack to client: %v\n", err)
			break
		}
	}

	fmt.Println("terminating connection")
}

// Handler creates a multiplexer for the server.
func Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/connection", handleConnectionRequest)
	return mux
}

func main() {
	var err error
	tlsConfig := &tls.Config{}

	fmt.Printf("#####----- IP Address is %v -----#####\n", GetOutboundIP())

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
