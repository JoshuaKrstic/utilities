package main

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/golang-jwt/jwt/v4"
)

const (
	socketPath     = "/run/container_launcher/teeserver.sock"
	expectedIssuer = "https://storage.googleapis.com/aws_token_bucket/aws_token_testing"
	wellKnownPath  = "/.well-known/openid-configuration"
)

type jwksFile struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	N   string `json:"n"`   // "nMMTBwJ7H6Id8zUCZd-L7uoNyz9b7lvoyse9izD9l2rtOhWLWbiG-7pKeYJyHeEpilHP4KdQMfUo8JCwhd-OMW0be_XtEu3jXEFjuq2YnPSPFk326eTfENtUc6qJohyMnfKkcOcY_kTE11jM81-fsqtBKjO_KiSkcmAO4wJJb8pHOjue3JCP09ZANL1uN4TuxbM2ibcyf25ODt3WQn54SRQTV0wn098Y5VDU-dzyeKYBNfL14iP0LiXBRfHd4YtEaGV9SBUuVhXdhx1eF0efztCNNz0GSLS2AEPLQduVuFoUImP4s51YdO9TPeeQ3hI8aGpOdC0syxmZ7LsL0rHE1Q",
	E   string `json:"e"`   // "AQAB" or 65537 as an int
	Kid string `json:"kid"` // "1f12fa916c3a0ef585894b4b420ad17dc9d6cdf5",

	// Unused fields:
	// Alg string `json:"alg"` // "RS256",
	// Kty string `json:"kty"` // "RSA",
	// Use string `json:"use"` // "sig",
}

type wellKnown struct {
	JwksURI string `json:"jwks_uri"` // "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"

	// Unused fields:
	// Iss                                   string `json:"issuer"`                                // "https://confidentialcomputing.googleapis.com"
	// Subject_types_supported               string `json:"subject_types_supported"`               // [ "public" ]
	// Response_types_supported              string `json:"response_types_supported"`              // [ "id_token" ]
	// Claims_supported                      string `json:"claims_supported"`                      // [ "sub", "aud", "exp", "iat", "iss", "jti", "nbf", "dbgstat", "eat_nonce", "google_service_accounts", "hwmodel", "oemid", "secboot", "submods", "swname", "swversion" ]
	// Id_token_signing_alg_values_supported string `json:"id_token_signing_alg_values_supported"` // [ "RS256" ]
	// Scopes_supported                      string `json:"scopes_supported"`                      // [ "openid" ]
}

func getWellKnownFile() (wellKnown, error) {
	httpClient := http.Client{}
	resp, err := httpClient.Get(expectedIssuer + wellKnownPath)
	if err != nil {
		return wellKnown{}, fmt.Errorf("failed to get raw .well-known response: %w", err)
	}

	wellKnownJSON, err := io.ReadAll(resp.Body)
	if err != nil {
		return wellKnown{}, fmt.Errorf("failed to read .well-known response: %w", err)
	}

	wk := wellKnown{}
	json.Unmarshal(wellKnownJSON, &wk)
	return wk, nil
}

func getJWKFile() (jwksFile, error) {
	wk, err := getWellKnownFile()
	if err != nil {
		return jwksFile{}, fmt.Errorf("failed to get .well-known json: %w", err)
	}

	// Get JWK URI from .wellknown
	uri := wk.JwksURI
	fmt.Printf("jwks URI: %v\n", uri)

	httpClient := http.Client{}
	resp, err := httpClient.Get(uri)
	if err != nil {
		return jwksFile{}, fmt.Errorf("failed to get raw JWK response: %w", err)
	}

	jwkbytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return jwksFile{}, fmt.Errorf("failed to read JWK body: %w", err)
	}

	file := jwksFile{}
	err = json.Unmarshal(jwkbytes, &file)
	if err != nil {
		return jwksFile{}, fmt.Errorf("failed to unmarshall JWK content: %w", err)
	}

	return file, nil
}

// N and E are 'base64urlUInt' encoded: https://www.rfc-editor.org/rfc/rfc7518#section-6.3
func base64urlUIntDecode(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	z := new(big.Int)
	z.SetBytes(b)
	return z, nil
}

func getRSAPublicKeyFromJWKsFile(t *jwt.Token) (any, error) {
	keysfile, err := getJWKFile()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch the JWK file: %w", err)
	}

	// Multiple keys are present in this endpoint to allow for key rotation.
	// This method finds the key that was used for signing to pass to the validator.
	kid := t.Header["kid"]
	for _, key := range keysfile.Keys {
		if key.Kid != kid {
			continue // Select the key used for signing
		}

		n, err := base64urlUIntDecode(key.N)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key.N %w", err)
		}
		e, err := base64urlUIntDecode(key.E)
		if err != nil {
			return nil, fmt.Errorf("failed to decode key.E %w", err)
		}

		fmt.Printf("N and E: %v\n, %v\n", n, e)

		// The parser expects an rsa.PublicKey: https://github.com/golang-jwt/jwt/blob/main/rsa.go#L53
		// or an array of keys. We chose to show passing a single key in this example as its possible
		// not all validators accept multiple keys for validation.
		return &rsa.PublicKey{
			N: n,
			E: int(e.Int64()),
		}, nil
	}

	return nil, fmt.Errorf("failed to find key with kid '%v' from well-known endpoint", kid)
}

func decodeAndValidateToken(tokenBytes []byte, keyFunc func(t *jwt.Token) (any, error)) (*jwt.Token, error) {
	var err error
	fmt.Println("Unmarshalling token and checking its validity...")
	token, err := jwt.NewParser().Parse(string(tokenBytes), keyFunc)

	fmt.Printf("Token valid: %v\n", token.Valid)
	fmt.Printf("Token method: %v\n", token.Method)
	if token.Valid {
		return token, nil
	}
	if ve, ok := err.(*jwt.ValidationError); ok {
		if ve.Errors&jwt.ValidationErrorMalformed != 0 {
			return nil, fmt.Errorf("token format invalid. Please contact the Confidential Space team for assistance")
		}
		if ve.Errors&(jwt.ValidationErrorNotValidYet) != 0 {
			// If device time is not synchronized with the Attestation Service you may need to account for that here.
			return nil, errors.New("token is not active yet")
		}
		if ve.Errors&(jwt.ValidationErrorExpired) != 0 {
			return nil, fmt.Errorf("token is expired")
		}
		return nil, fmt.Errorf("unknown validation error: %v", err)
	}

	return nil, fmt.Errorf("couldn't handle this token or couldn't read a validation error: %v", err)
}

func main() {
	// Get a token from a workload running in Confidential Space
	tokenbytes := []byte("eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1IiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL2pvc2h0ZXN0YXVkaWVuY2UiLCJleHAiOjE3MDk5MzQyNTQsImh0dHBzOi8vYXdzLmFtYXpvbi5jb20vdGFncyI6eyJwcmluY2lwYWxfdGFncyI6eyJjb25maWRlbnRpYWxfc3BhY2Uuc3VwcG9ydF9hdHRyaWJ1dGVzIjpbIkxBVEVTVD1TVEFCTEU9VVNBQkxFIl0sImNvbnRhaW5lci5hcmdzIjpbImZvbyJdLCJjb250YWluZXIuZW52LmZvbyI6WyJiYXIiXSwiY29udGFpbmVyLmltYWdlX2RpZ2VzdCI6WyJzaGEyNTY6YWJjZGVmLi4uIl0sImNvbnRhaW5lci5pbWFnZV9zaWduYXR1cmVzIjpbIjEyMzo0NTYiXSwiZGJnc3RhdCI6WyJlbmFibGVkIl0sImdjZS5pbnN0YW5jZV9pZCI6WyIyMTc0ODk2MjI0MDczMzk3MTAxIl0sImdvb2dsZV9zZXJ2aWNlX2FjY291bnRzIjpbIjYyMDQzODU0NTg4OS1jb21wdXRlQGRldmVsb3Blci5nc2VydmljZWFjY291bnQuY29tPTYyMDQzODU0NTg4OS1jb21wdXRlQGRldmVsb3Blci5nc2VydmljZWFjY291bnQuY29tIl0sImh3bW9kZWwiOlsiR0NQX0FNRF9TRVYiXSwic2VjYm9vdCI6WyJ0cnVlIl0sInN3bmFtZSI6WyJDT05GSURFTlRJQUxfU1BBQ0UiXX19LCJpYXQiOjE3MDc5MzQyNTQsImlzcyI6Imh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9hd3NfdG9rZW5fYnVja2V0L2F3c190b2tlbl90ZXN0aW5nIiwic3ViIjoiUG9uZ3JlZWJhZGVlbkRpbmgifQ.NcMwpEVqS1Bys1VoBRpBeBrxXteNURJVgLmdh5xyk59mtkZ9wcI09VR6AgeomAjVWQABvQIout18r85sOhI4Ea5puLICnxowKc047UG6c4q5W1NrmQ5WvTsdIMRfrwDuaTzqKc5rPn-TWvhVRk840wCjiOxJmcbZUfEhC4Oysh2P2tc3wvM_wGB5EpLdNxlVlQllay2UALN54TUn4r_UtVIgLaJgm3MG4SC5-ZDbV6ILx67P_CsS1BHQFcktZCgTcVSpC29Gn-XyYJH26LpLV_XbpMTZA2gOxebV0YkdQ6nqh_UIjAvKBqUqx-s_t2pEQLJzSopudAkjpT4BSNYgpw")

	// Write a method to return a public key from the well-known endpoint
	keyFunc := getRSAPublicKeyFromJWKsFile

	// Verify properties of the original Confidential Space workload that generated the attestation
	// using the token claims.
	token, err := decodeAndValidateToken(tokenbytes, keyFunc)
	if err != nil {
		panic(err)
	}

	claimsString, err := json.MarshalIndent(token.Claims, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Println(string(claimsString))
}
