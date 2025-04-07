// package main is a test workload that will print out the success status of an AWS decrypt operation.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
)

const (
	// Token Request Constants
	socketPath       = "/run/container_launcher/teeserver.sock"
	itaTokenEndpoint = "http://localhost/v1/intel/token"
	gcaTokenEndpoint = "http://localhost/v1/token"
	contentType      = "application/json"
	unixNetwork      = "unix"

	// Workload Metadata Constants
	customAudienceVariable = "custom_audience"
)

type tokenRequest struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}

func getCustomToken(path string, body string) ([]byte, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial(unixNetwork, socketPath)
			},
		},
	}

	resp, err := httpClient.Post(path, contentType, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to get raw custom token response: %w", err)
	}

	defer resp.Body.Close()

	fmt.Printf("Got response from TEE server, code: %v\n", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to get a valid attestation token, status code: %v", resp.StatusCode)
	}

	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read custom token body: %w", err)
	}

	return tokenbytes, nil
}

func main() {
	audience, ok := os.LookupEnv(customAudienceVariable)
	if !ok {
		panic(fmt.Errorf("unable to find the custom audience variable. A variable with the name %v is required for this workload", customAudienceVariable))
	}

	// Get token from the launcher
	body := tokenRequest{
		Audience:  audience,
		TokenType: "OIDC",
	}

	val, err := json.Marshal(body)
	if err != nil {
		err = fmt.Errorf("failed to marshal custom request into a request body. Attempted to marshal '%v', got err: %w", body, err)
		panic(err)
	}

	itaToken, itaErr := getCustomToken(itaTokenEndpoint, string(val))
	gcaToken, gcaErr := getCustomToken(gcaTokenEndpoint, string(val))
	if itaErr != nil {
		fmt.Printf("failed to get ITA token: %v\n", itaErr)
	} else {
		fmt.Printf("ITA Token recieved: %v\n", string(itaToken))
	}

	if gcaErr != nil {
		fmt.Printf("failed to get GCA token: %v\n", gcaErr)
	} else {
		fmt.Printf("ITA Token recieved: %v\n", string(gcaToken))
	}

	structuredItaToken := jwt.MapClaims{}
	json.Unmarshal(itaToken, &structuredItaToken)

	structuredGcaToken := jwt.MapClaims{}
	json.Unmarshal(gcaToken, &structuredGcaToken)

	diff := cmp.Diff(structuredItaToken, structuredGcaToken)
	fmt.Printf("Token Diff: %v\n", diff)
}
