package main

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"github.com/joshuakrstic/utilities/jwtvalidate"
)

var (
	mySensitiveDataFile = "./mysensitivedata"
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

func getEKMHashFromRequest(c *websocket.Conn) ([]byte, error) {
	conn, ok := c.NetConn().(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("failed to cast NetConn to *tls.Conn")
	}

	state := conn.ConnectionState()
	ekm, err := state.ExportKeyingMaterial("testing_nonce", nil, 32)
	if err != nil {
		return nil, fmt.Errorf("failed to get EKM from TLS connection: %w", err)
	}

	sha := sha256.New()
	sha.Write(ekm)
	hash := sha.Sum(nil)

	return hash, nil
}

// TODO - add runtime flag to get URL dynamically
func main() {
	url := "wss://10.140.0.13:8081/connection"

	tlsconfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	dialer := websocket.Dialer{
		TLSClientConfig: tlsconfig,
	}

	conn, resp, err := dialer.Dial(url, nil)
	if err != nil {
		fmt.Printf("Failed to dial to url %s, err %v\n", url, err)
		return
	}

	defer conn.Close()

	fmt.Printf("Got a reply %v\n", resp)

	v := jwtvalidate.NewValidator("https://confidentialcomputing.googleapis.com/")

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

		// Check that the content contains the expected nonce. Content is an OIDC token.
		token, err := v.DecodeAndValidateToken(content)
		if err != nil {
			fmt.Printf("failed to decode and validate token: %v\n. Token: %v\n", err, token)
			return
		}

		fmt.Println("Token validated. Checking nonce for EKM....")

		ekm, err := getEKMHashFromRequest(conn)
		if err != nil {
			fmt.Printf("failed to get EKM from outbound request: %v", err)
			return
		}

		err = checkTokenNonce(token, string(ekm))
		if err != nil {
			fmt.Println("failed to validate the token nonce. Not sending sensitive data")
			return
		}

		fmt.Println("Validated the nonce with the expected EKM. Sending sensitive data")
	}

}
