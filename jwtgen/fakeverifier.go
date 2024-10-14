package fakeverifier

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Shell command here:
// awstest () {
// 	aws sts assume-role-with-web-identity --role-arn arn:aws:iam::232510754029:role/mealcorp-keyaccess --role-session-name 101 --web-identity-token $1
//   }

func addStandardClaims(claims jwt.MapClaims) {
	t := time.Now().Unix() - 1 // -1 second to avoid tokens being used before their issued time
	claims["iat"] = t
	claims["exp"] = t + 60*60
	claims["iss"] = "https://storage.googleapis.com/aws_token_bucket/aws_token_testing"
	claims["aud"] = "https://meal.corp"
}

func updateHeader(token *jwt.Token) {
	token.Header["kid"] = "12345"
}

func GenerateTokenWithClaims(pemCert []byte, claims jwt.MapClaims) (string, error) {
	addStandardClaims(claims)
	signingMethod := jwt.SigningMethodRS256
	token := jwt.NewWithClaims(signingMethod, claims)

	updateHeader(token)

	p, _ := pem.Decode([]byte(pemCert))
	if p == nil {
		return "", fmt.Errorf("failed to decode key")
	}

	key, err := x509.ParsePKCS1PrivateKey(p.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %v", err)
	}

	tokenstring, err := token.SignedString(key)

	if err != nil {
		return "", fmt.Errorf("failed to sign token: %v", err)
	}

	return tokenstring, nil
}
