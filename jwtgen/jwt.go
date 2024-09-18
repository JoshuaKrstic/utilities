package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func main() {
	t := time.Now().Unix() - 1 // -1 second to avoid tokens being used before their issued time
	signingMethod := jwt.SigningMethodRS256
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"aud":     "https://meal.corp",
		"iss":     "https://storage.googleapis.com/aws_token_bucket/aws_token_testing",
		"sub":     "https://www.googleapis.com/compute/v1/projects/TESTPROJECTID/zones/us-central1-a/instances/TESTSUB",
		"iat":     t,
		"exp":     t + 60*60,
		"dbgstat": "disabled-since-boot",
		"eat_nonce": []string{
			"NONCE1abcdef",
			"NONCE2abcdef",
		},
		"eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
		"google_service_accounts": []string{
			"PROJECT_ID-compute@developer.gserviceaccount.com",
		},
		"hwmodel": "GCP_AMD_SEV",
		"oemid":   11129,
		"secboot": true,
		"submods": jwt.MapClaims{
			"confidential_space": jwt.MapClaims{
				"monitoring_enabled": jwt.MapClaims{
					"memory": false,
				},
				"support_attributes": []string{
					"LATEST",
					"STABLE",
					"USABLE",
				},
			},
			"container": jwt.MapClaims{
				"args": []string{
					"/customnonce",
					"/docker-entrypoint.sh",
					"nginx",
					"-g",
					"daemon off;",
				},
				"env": jwt.MapClaims{
					"HOSTNAME":      "HOST_NAME",
					"NGINX_VERSION": "1.27.0",
					"NJS_RELEASE":   "2~bookworm",
					"NJS_VERSION":   "0.8.4",
					"PATH":          "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
					"PKG_RELEASE":   "2~bookworm",
				},
				"image_digest":    "sha256:67682bda769fae1ccf5183192b8daf37b64cae99c6c3302650f6f8bf5f0f95df",
				"image_id":        "sha256:fffffc90d343cbcb01a5032edac86db5998c536cd0a366514121a45c6723765c",
				"image_reference": "docker.io/library/nginx:latest",
				"image_signatures": []jwt.MapClaims{
					jwt.MapClaims{
						"key_id":              "<hexadecimal-sha256-fingerprint-public-key1>",
						"signature":           "<base64-encoded-signature>",
						"signature_algorithm": "RSASSA_PSS_SHA256",
					},
					jwt.MapClaims{
						"key_id":              "<hexadecimal-sha256-fingerprint-public-key2>",
						"signature":           "<base64-encoded-signature>",
						"signature_algorithm": "RSASSA_PSS_SHA256",
					},
					jwt.MapClaims{
						"key_id":              "<hexadecimal-sha256-fingerprint-public-key3>",
						"signature":           "<base64-encoded-signature>",
						"signature_algorithm": "ECDSA_P256_SHA256",
					},
				},
				"restart_policy": "Never",
			},
			"gce": jwt.MapClaims{
				"instance_id":    "INSTANCE_ID",
				"instance_name":  "INSTANCE_NAME",
				"project_id":     "PROJECT_ID",
				"project_number": "PROJECT_NUMBER",
				"zone":           "us-central1-a",
			},
		},
		"swname": "CONFIDENTIAL_SPACE",
		"swversion": []string{
			"240500",
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

// "https://aws.amazon.com/tags": jwt.MapClaims {
// 	"principal_tags": jwt.MapClaims {
// 		"swname":                                []string{"CONFIDENTIAL_SPACE"},
// 		"hwmodel":                               []string{"GCP_AMD_SEV"},
// 		"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE="},
// 		"container.image_digest":                []string{"sha256:notthesamehash9949d43fd51dde2a5b66db9b695ef5bfe525cf8576d54ffaa9"},
// 		"swversion":                             []string{"230902"},
// 		"gce.zone":                              []string{"us-east4-c"},
// 	},
// },
