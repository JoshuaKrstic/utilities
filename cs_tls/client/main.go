package main

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/joshuakrstic/utilities/jwtvalidate"
)

const (
	mySensitiveDataFile = "./mysensitivedata"
	ip_addr_env_var     = "remote_ip_addr"
)

func readSensitveData() ([]byte, error) {
	file, err := os.ReadFile(mySensitiveDataFile)
	if err != nil {
		fmt.Println("Failed to read in sensitive data file")
		return nil, err
	}

	return file, nil
}

func checkTokenNonce(t *jwt.Token, ekm string) error {
	// This method just checks that the nonce is valid.
	// In your application, you should check the other claims are valid as well.
	var claims jwt.MapClaims
	var ok bool
	if claims, ok = t.Claims.(jwt.MapClaims); !ok {
		return fmt.Errorf("failed to get the claims from the JWT")
	}

	nonce := claims["eat_nonce"]

	if nonce != ekm {
		return fmt.Errorf("the nonce in the token '%v' does not equal the expected EKM '%v'", nonce, ekm)
	}

	return nil
}

func getEKMHashFromConn(c *websocket.Conn) (string, error) {
	conn, ok := c.NetConn().(*tls.Conn)
	if !ok {
		return "", fmt.Errorf("failed to cast NetConn to *tls.Conn")
	}

	state := conn.ConnectionState()
	ekm, err := state.ExportKeyingMaterial("testing_nonce", nil, 32)
	if err != nil {
		return "", fmt.Errorf("failed to get EKM from TLS connection: %w", err)
	}

	sha := sha256.New()
	sha.Write(ekm)
	hash := base64.StdEncoding.EncodeToString(sha.Sum(nil))

	return hash, nil
}

func handleTokenMessageType(conn *websocket.Conn, content []byte) error {
	v := jwtvalidate.NewValidator("https://confidentialcomputing.googleapis.com/")

	// Check that the content contains the expected nonce. Content is an OIDC token.
	token, err := v.DecodeAndValidateToken(content)
	if err != nil {
		err := fmt.Errorf("failed to decode and validate token: %w\n. Token: %v", err, token)
		return err
	}

	fmt.Println("Token validated. Checking nonce for EKM....")

	ekm, err := getEKMHashFromConn(conn)
	if err != nil {
		err := fmt.Errorf("failed to get EKM from outbound request: %w", err)
		return err
	}

	err = checkTokenNonce(token, string(ekm))
	if err != nil {
		err := fmt.Errorf("failed to validate the token nonce. Not sending sensitive data. err: %w", err)
		return err
	}

	return nil
}

// TODO - add runtime flag to get URL dynamically
func main() {
	fmt.Println("Initializing client...")

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
	}
	dialer := websocket.Dialer{
		TLSClientConfig:  tlsconfig,
		HandshakeTimeout: 5 * time.Second,
	}

	ip_addr := os.Getenv(ip_addr_env_var)
	url := fmt.Sprintf("wss://%s:8081/connection", ip_addr)

	fmt.Printf("Attempting to dial to url %v...\n", url)
	conn, _, err := dialer.Dial(url, nil)
	if err != nil {
		fmt.Printf("Failed to dial to url %s, err %v\n", url, err)
		return
	}

	defer conn.Close()

	_, content, err := conn.ReadMessage()
	if err != nil {
		fmt.Printf("failed to read message from the connection: %v\n", err)
	}

	handleTokenMessageType(conn, content)
	fmt.Println("Validated the nonce with the expected EKM. Sending sensitive data")

	data, err := readSensitveData()
	if err != nil {
		fmt.Printf("Failed to read data from the file: %v\n", err)
	}
	conn.WriteMessage(2, data)
	fmt.Println("Sent payload. Closing the connection")
	conn.Close()
}
