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
)

const (
	// Token Request Constants
	socketPath       = "/run/container_launcher/teeserver.sock"
	itaTokenEndpoint = "http://localhost/v1/intel/token"
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

func getCustomITATokenBytes(body string) (string, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial(unixNetwork, socketPath)
			},
		},
	}

	resp, err := httpClient.Post(itaTokenEndpoint, contentType, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("failed to get raw custom token response: %w", err)
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("failed to get a valid attestation token, status code: %v", resp.StatusCode)
	}

	tokenbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read custom token body: %w", err)
	}

	return string(tokenbytes), nil
}

func main() {
	audience, ok := os.LookupEnv(customAudienceVariable)
	if !ok {
		panic(fmt.Errorf("unable to find the custom audience variable. A variable with the name %v is required for this workload", customAudienceVariable))
	}

	// Get token from the launcher
	body := tokenRequest{
		Audience: audience,
	}

	val, err := json.Marshal(body)
	if err != nil {
		err = fmt.Errorf("failed to marshal custom request into a request body. Attempted to marshal '%v', got err: %w", body, err)
		panic(err)
	}

	token, err := getCustomITATokenBytes(string(val))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Token recieved: %v", token)
}
