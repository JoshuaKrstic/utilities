package main

import (
	"encoding/json"
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

func checkOIDCToken(tokenbytes []byte, ekmhash string) (bool, error) {
	mapClaims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(string(tokenbytes), mapClaims)
	if err != nil {
		return false, err
	}
	claimsString, err := json.MarshalIndent(mapClaims, "", "  ")
	if err != nil {
		return false, err
	}

}

// todo - get IP address from a flag

func main() {
	url := "https://10.140.0.13:8081/connection"
	c, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		fmt.Printf("Error connecting to WebSocket server: %v\n", err)
	}
	defer c.Close()

	for {
		messageType, content, err := c.ReadMessage()
		if err != nil {
			fmt.Printf("failed to read message from the connection: %v\n", err)
			break
		}

		if messageType == 0 {
			fmt.Println("Received EOL message type")
			c.WriteMessage(0, []byte("bye"))
			break
		}

		// Check that the content contains the expected nonce. Content is an OIDC token.
	}
}
