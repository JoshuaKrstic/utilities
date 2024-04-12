package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v4"
)

func main() {
	signingMethod := jwt.SigningMethodRS256
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"aud": "https://meal.corp",
		"iss": "https://storage.googleapis.com/aws_token_bucket/aws_token_testing",
		"sub": "thisisatestsub",
		"iat": 1712857253,
		"exp": 1719857253,
		"https://aws.amazon.com/tags": jwt.MapClaims{
			"principal_tags": jwt.MapClaims{
				"swname":                                []string{"CONFIDENTIAL_SPACE"},
				"hwmodel":                               []string{"GCP_AMD_SEV"},
				"confidential_space.support_attributes": []string{"{LATEST,STABLE,USABLE,}"},
				"container.image_digest":                []string{"sha256:notthesamehash9949d43fd51dde2a5b66db9b695ef5bfe525cf8576d54ffaa9"},
				"swversion":                             []string{"230902"},
				"gce.zone":                              []string{"us-east4-c"},
				"gce.project_id":                        []string{"this-is-a-long-project-id"},
			},
			// "transitive_tag_keys": []string{"secboot"},
		},
	})

	token.Header["kid"] = "12345"

	privateKey, err := os.ReadFile("mykey.pem")
	if err != nil {
		fmt.Printf("failed to read keyfile: %v\n", err)
		return
	}

	p, _ := pem.Decode([]byte(privateKey))
	if p == nil {
		fmt.Println("failed to decode key")
		return
	}

	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		fmt.Printf("failed to parse private key: %v\n", err)
		return
	}
	//fmt.Printf("Parsed RSA key: %v\n", key)

	//pbytes := []byte(p.Bytes)
	tokenstring, err := token.SignedString(key)

	if err != nil {
		fmt.Printf("failed to sign token: %v\n", err)
		return
	}

	//fmt.Println("Token signed successfully")
	fmt.Println(tokenstring)
}
