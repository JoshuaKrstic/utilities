package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// Shell command here:
// awstest () {
// 	aws sts assume-role-with-web-identity --role-arn arn:aws:iam::533267259198:role/ITATesting --role-session-name 101 --web-identity-token $1
//   }

// token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
// 	"aud": "https://meal.corp",
// 	"iss": "https://storage.googleapis.com/aws_token_bucket/aws_token_testing",
// 	"sub": "https://www.googleapis.com/compute/v1/projects/TESTPROJECTID/zones/us-central1-a/instances/TESTSUB",
// 	"iat": t,
// 	"exp": t + 60*60,
// 	"https://aws.amazon.com/tags": jwt.MapClaims{
// 		"principal_tags": jwt.MapClaims{
// 			"hwmodel":                               []string{"GCP_INTEL_TDX"},
// 			"swname":                                []string{"CONFIDENTIAL_SPACE"},
// 			"swversion":                             []string{"240900"},
// 			"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
// 			"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
// 			"gce.zone":                              []string{"northamerica-northeast1-a"},
// 			"container.signatures.key_ids":          []string{"6b1f357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9=551f357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=551f357b59e9400000000"},
// 			//"container.image_digest":                []string{"sha256:d2b1c146f68097ba33d16bbd76e4953a91d003a552ff055c9c505fd436216ee2"},
// 		},
// 	},
// 	"dbgstat": "disabled-since-boot",
// 	"eat_nonce": []string{
// 		"NONCE1abcdef",
// 		"NONCE2abcdef",
// 	},
// 	"eat_profile": "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
// 	"google_service_accounts": []string{
// 		"PROJECT_ID-compute@developer.gserviceaccount.com",
// 	},
// 	"hwmodel": "GCP_AMD_SEV",
// 	"oemid":   11129,
// 	"secboot": true,
// 	"submods": jwt.MapClaims{
// 		"confidential_space": jwt.MapClaims{
// 			"monitoring_enabled": jwt.MapClaims{
// 				"memory": false,
// 			},
// 			"support_attributes": []string{
// 				"LATEST",
// 				"STABLE",
// 				"USABLE",
// 			},
// 		},
// 		"container": jwt.MapClaims{
// 			"args": []string{
// 				"/customnonce",
// 				"/docker-entrypoint.sh",
// 				"nginx",
// 				"-g",
// 				"daemon off;",
// 			},
// 			"env": jwt.MapClaims{
// 				"HOSTNAME":      "HOST_NAME",
// 				"NGINX_VERSION": "1.27.0",
// 				"NJS_RELEASE":   "2~bookworm",
// 				"NJS_VERSION":   "0.8.4",
// 				"PATH":          "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
// 				"PKG_RELEASE":   "2~bookworm",
// 			},
// 			"image_digest":    "sha256:67682bda769fae1ccf5183192b8daf37b64cae99c6c3302650f6f8bf5f0f95df",
// 			"image_id":        "sha256:fffffc90d343cbcb01a5032edac86db5998c536cd0a366514121a45c6723765c",
// 			"image_reference": "docker.io/library/nginx:latest",
// 			"image_signatures": []jwt.MapClaims{
// 				{
// 					"key_id":              "ABCD057b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9",
// 					"signature":           "ABCD0BhMA8g6xgWDLtr/RbHRdpv26wVos8VuZ/aRZ2uhQldRAiEAgDA4kROlJJ298p1wrmJWiuxpiznWr7c1qHVbMsL02a0=",
// 					"signature_algorithm": "ECDSA_P256_SHA256",
// 				},
// 				{
// 					"key_id":              "EFGH057b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9",
// 					"signature":           "EFGH0BhMA8g6xgWDLtr/RbHRdpv26wVos8VuZ/aRZ2uhQldRAiEAgDA4kROlJJ298p1wrmJWiuxpiznWr7c1qHVbMsL02a0=",
// 					"signature_algorithm": "RSASSA_PSS_SHA256",
// 				},
// 				{
// 					"key_id":              "IJKL057b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9",
// 					"signature":           "IJKL0BhMA8g6xgWDLtr/RbHRdpv26wVos8VuZ/aRZ2uhQldRAiEAgDA4kROlJJ298p1wrmJWiuxpiznWr7c1qHVbMsL02a0=",
// 					"signature_algorithm": "ECDSA_P256_SHA256",
// 				},
// 			},
// 			"restart_policy": "Never",
// 		},
// 		"gce": jwt.MapClaims{
// 			"instance_id":    "INSTANCE_ID",
// 			"instance_name":  "INSTANCE_NAME",
// 			"project_id":     "PROJECT_ID",
// 			"project_number": "PROJECT_NUMBER",
// 			"zone":           "us-central1-a",
// 		},
// 	},
// 	"swname": "CONFIDENTIAL_SPACE",
// 	"swversion": []string{
// 		"240500",
// 	},
// })

var body = `{
  "aud": "https://meal.corp",
  "dbgstat": "disabled-since-boot",
  "eat_profile": "https://portal.trustauthority.intel.com/eat_profile.html",
  "google_service_accounts": [
    "service-account-workload-run@amber-gcp-hybrid.iam.gserviceaccount.com"
  ],
  "https://aws.amazon.com/tags": {
    "principal_tags": {
      "confidential_space.support_attributes": [
        "EXPERIMENTAL=SOMETHING"
      ],
      "container.image_digest": [
        "sha256:179ee6ff3b1adf922647f85c52426a138005603f267f5b4f6520867ebad64fe4"
      ],
      "container.signatures.key_ids": [
        ""
      ],
      "gce.project_id": [
        "amber-gcp-hybrid"
      ],
      "gce.zone": [
        "us-central1-a"
      ],
      "hwmodel": [
        "INTEL_TDX"
      ],
      "swname": [
        "CONFIDENTIAL_SPACE"
      ],
      "swversion": [
        "654321"
      ]
    }
  },
  "hwmodel": "INTEL_TDX",
  "oemid": 11129,
  "secboot": true,
  "sub": "https://www.googleapis.com/compute/v1/projects/amber-gcp-hybrid/zones/us-central1-a/instances/jerry-gcpcs-hardened",
  "submods": {
    "confidential_space": {
      "monitoring_enabled": {
        "memory": false
      },
      "support_attributes": [
        "EXPERIMENTAL",
        "SOMETHING"
      ]
    },
    "container": {
      "args": [
        "/sampleapp"
      ],
      "env": {
        "HOSTNAME": "jerry-gcpcs-hardened",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "env_bar": "val_bar"
      },
      "image_digest": "sha256:179ee6ff3b1adf922647f85c52426a138005603f267f5b4f6520867ebad64fe4",
      "image_id": "sha256:a82421264bab4becfaf3b5a2be3cc6d947e92c7613de0d6e069302717c71163d",
      "image_reference": "us-docker.pkg.dev/amber-gcp-hybrid/ita-repo/get-token:build0424.2",
      "restart_policy": "Never"
    },
    "gce": {
      "instance_id": "2626271027377675994",
      "instance_name": "jerry-gcpcs-hardened",
      "project_id": "amber-gcp-hybrid",
      "project_number": "410245496121",
      "zone": "us-central1-a"
    }
  },
  "swname": "CONFIDENTIAL_SPACE",
  "swversion": [
    "654321"
  ],
  "tdx": {
    "attester_tcb_date": "2024-03-13T00:00:00Z",
    "attester_tcb_status": "UpToDate",
    "gcp_attester_tcb_date": "2024-03-13T00:00:00Z",
    "gcp_attester_tcb_status": "UpToDate"
  },
  "verifier_instance_ids": [
    "d1c3ca42-26b8-468c-b8c3-018984cf0bc2",
    "0a1b843f-3be2-4235-94cf-bc01209032c9",
    "095a35f8-5dd8-4a3d-b4ec-053b320866cf",
    "6c9ba49b-5780-45b5-aaa8-73a7427955bc",
    "ee6ec158-1cae-43a7-b3f8-ceeaa06c34ef",
    "c399bd74-0948-4304-a8b9-24f720b7ee20",
    "c399bd74-0948-4304-a8b9-24f720b7ee20",
    "1f4d0c5c-0d9e-4c0d-b2aa-f63d1c7a161d"
  ],
  "exp": 1746126197,
  "jti": "abea7a24-e95a-4d2d-a5e1-c51361a675fb",
  "iat": 1746124397,
  "iss": "https://amber-dev02-user10.ita-dev.adsdcsp.com",
  "nbf": 1746124397
}`

func getMapClaims(j string) (jwt.MapClaims, error) {
	var claimsData map[string]interface{}

	err := json.Unmarshal([]byte(j), &claimsData)
	if err != nil {
		return nil, err
	}

	claims := jwt.MapClaims{}
	for k, v := range claimsData {
		claims[k] = v
	}

	return claims, nil
}

func generateToken(claims jwt.MapClaims) *jwt.Token {
	t := time.Now().Unix() - 1 // -1 second to avoid tokens being used before their issued time
	signingMethod := jwt.SigningMethodRS256

	claims["iat"] = t
	claims["exp"] = t + 60*60
	claims["aud"] = "https://meal.corp"
	claims["iss"] = "https://storage.googleapis.com/aws_token_bucket/aws_token_testing"

	token := jwt.NewWithClaims(signingMethod, claims)
	token.Header["kid"] = "12345"
	return token
}

func main() {
	claims, err := getMapClaims(body)
	if err != nil {
		fmt.Printf("failed to get map claims: %v\n", err)
		return
	}
	token := generateToken(claims)

	privateKey, err := os.ReadFile("../data/mykey.pem")
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

	tokenstring, err := token.SignedString(key)

	if err != nil {
		fmt.Printf("failed to sign token: %v\n", err)
		return
	}

	fmt.Println(tokenstring)
}
