package fakeverifier

import (
	"fakeverifier"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang-jwt/jwt/v4"
)

const (
	// AWS Session
	awsRegion      = "us-east-2"
	awsSessionName = "integration_test"
	// S3
	s3Bucket = "corporation-corp-employee-data"
	s3String = "ciphertext"
)

func baseToken() jwt.MapClaims {
	return jwt.MapClaims{
		"sub":     "https://www.googleapis.com/compute/v1/projects/TESTPROJECTID/zones/us-central1-a/instances/TESTSUB",
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
					{
						"key_id":              "ABCD057b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9",
						"signature":           "ABCD0BhMA8g6xgWDLtr/RbHRdpv26wVos8VuZ/aRZ2uhQldRAiEAgDA4kROlJJ298p1wrmJWiuxpiznWr7c1qHVbMsL02a0=",
						"signature_algorithm": "ECDSA_P256_SHA256",
					},
					{
						"key_id":              "EFGH057b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9",
						"signature":           "EFGH0BhMA8g6xgWDLtr/RbHRdpv26wVos8VuZ/aRZ2uhQldRAiEAgDA4kROlJJ298p1wrmJWiuxpiznWr7c1qHVbMsL02a0=",
						"signature_algorithm": "RSASSA_PSS_SHA256",
					},
					{
						"key_id":              "IJKL057b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9",
						"signature":           "IJKL0BhMA8g6xgWDLtr/RbHRdpv26wVos8VuZ/aRZ2uhQldRAiEAgDA4kROlJJ298p1wrmJWiuxpiznWr7c1qHVbMsL02a0=",
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
	}
}

func baseTokenMergedWith(claims jwt.MapClaims) jwt.MapClaims {
	b := baseToken()
	for k, v := range claims {
		b[k] = v
	}
	return b
}

func TestTokens(t *testing.T) {
	type testcase struct {
		name        string
		wantFailure bool
		roleArn     string
		claims      jwt.MapClaims
	}
	testcases := []testcase{
		{
			name:        "Happy path, max length claims",
			wantFailure: false,
			roleArn:     "arn:aws:iam::232510754029:role/mealcorp-keyaccess",
			claims: baseTokenMergedWith(jwt.MapClaims{
				"https://aws.amazon.com/tags": jwt.MapClaims{
					"principal_tags": jwt.MapClaims{
						"hwmodel":                               []string{"GCP_INTEL_TDX"},
						"swname":                                []string{"CONFIDENTIAL_SPACE"},
						"swversion":                             []string{"240900"},
						"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
						"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
						"gce.zone":                              []string{"northamerica-northeast1-a"},
						"container.signatures.key_ids":          []string{"abcd357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9=efgh357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=ijkl357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555"},
					},
				},
			}),
		},
		{
			name:        "Signatures in reversed order",
			wantFailure: true,
			roleArn:     "arn:aws:iam::232510754029:role/mealcorp-keyaccess",
			claims: baseTokenMergedWith(jwt.MapClaims{
				"https://aws.amazon.com/tags": jwt.MapClaims{
					"principal_tags": jwt.MapClaims{
						"hwmodel":                               []string{"GCP_INTEL_TDX"},
						"swname":                                []string{"CONFIDENTIAL_SPACE"},
						"swversion":                             []string{"240900"},
						"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
						"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
						"gce.zone":                              []string{"northamerica-northeast1-a"},
						"container.signatures.key_ids":          []string{"ijkl357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=efgh357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=abcd357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9"},
					},
				},
			}),
		},
		{
			name:        "Signatures in another order",
			wantFailure: true,
			roleArn:     "arn:aws:iam::232510754029:role/mealcorp-keyaccess",
			claims: baseTokenMergedWith(jwt.MapClaims{
				"https://aws.amazon.com/tags": jwt.MapClaims{
					"principal_tags": jwt.MapClaims{
						"hwmodel":                               []string{"GCP_INTEL_TDX"},
						"swname":                                []string{"CONFIDENTIAL_SPACE"},
						"swversion":                             []string{"240900"},
						"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
						"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
						"gce.zone":                              []string{"northamerica-northeast1-a"},
						"container.signatures.key_ids":          []string{"abcd357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9=ijkl357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555"},
					},
				},
			}),
		},
		{
			name:        "Missing one signature results in rejection",
			wantFailure: true,
			roleArn:     "arn:aws:iam::232510754029:role/mealcorp-keyaccess",
			claims: baseTokenMergedWith(jwt.MapClaims{
				"https://aws.amazon.com/tags": jwt.MapClaims{
					"principal_tags": jwt.MapClaims{
						"hwmodel":                               []string{"GCP_INTEL_TDX"},
						"swname":                                []string{"CONFIDENTIAL_SPACE"},
						"swversion":                             []string{"240900"},
						"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
						"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
						"gce.zone":                              []string{"northamerica-northeast1-a"},
						"container.signatures.key_ids":          []string{"ijkl357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=efgh357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555"},
					},
				},
			}),
		},
		{
			name:        "Too many signatures",
			wantFailure: true,
			roleArn:     "arn:aws:iam::232510754029:role/mealcorp-keyaccess",
			claims: baseTokenMergedWith(jwt.MapClaims{
				"https://aws.amazon.com/tags": jwt.MapClaims{
					"principal_tags": jwt.MapClaims{
						"hwmodel":                               []string{"GCP_INTEL_TDX"},
						"swname":                                []string{"CONFIDENTIAL_SPACE"},
						"swversion":                             []string{"240900"},
						"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
						"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
						"gce.zone":                              []string{"northamerica-northeast1-a"},
						"container.signatures.key_ids":          []string{"abcd357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9=efgh357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=ijkl357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=mnop357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555"},
					},
				},
			}),
		},
		{
			name:        "Token that works on the command line, one char shorter than the breaking token",
			wantFailure: false,
			roleArn:     "arn:aws:iam::232510754029:role/mealcorp-keyaccess",
			claims: baseTokenMergedWith(jwt.MapClaims{
				"https://aws.amazon.com/tags": jwt.MapClaims{
					"principal_tags": jwt.MapClaims{
						"hwmodel":                               []string{"GCP_INTEL_TDX"},
						"swname":                                []string{"CONFIDENTIAL_SPACE"},
						"swversion":                             []string{"240900"},
						"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
						"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
						"gce.zone":                              []string{"northamerica-northeast1-a"},
						"container.signatures.key_ids":          []string{"6b1f357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9=551f357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=551f357b59e940000000"},
					},
				},
			}),
		},
		{
			name:        "Token that breaks the command line, one character longer than the breaking token",
			wantFailure: false,
			roleArn:     "arn:aws:iam::232510754029:role/mealcorp-keyaccess",
			claims: baseTokenMergedWith(jwt.MapClaims{
				"https://aws.amazon.com/tags": jwt.MapClaims{
					"principal_tags": jwt.MapClaims{
						"hwmodel":                               []string{"GCP_INTEL_TDX"},
						"swname":                                []string{"CONFIDENTIAL_SPACE"},
						"swversion":                             []string{"240900"},
						"confidential_space.support_attributes": []string{"LATEST=STABLE=USABLE"},
						"gce.project_id":                        []string{"projectidpaddedto30chars0000000000000000000"},
						"gce.zone":                              []string{"northamerica-northeast1-a"},
						"container.signatures.key_ids":          []string{"6b1f357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b25f9=551f357b59e9407fb017ca0e3e783b2bd5acbfea6c83dd82971a4150df5b2555=551f357b59e9400000000"},
					},
				},
			}),
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			privateKey, err := os.ReadFile("../data/mykey.pem")
			if err != nil {
				t.Fatalf("failed to generate token %v", err)
			}
			token, err := fakeverifier.GenerateTokenWithClaims(privateKey, tc.claims)
			//t.Logf("token length: %v", len(token))
			//t.Logf("token: %v", token)

			if err != nil {
				t.Fatalf("failed to generate token %v", err)
			}

			dir := t.TempDir()
			tokenPath := fmt.Sprintf("%s/token", dir)
			writeTokenToPath(token, tokenPath)

			sess, _ := session.NewSession(&aws.Config{
				Region: aws.String(awsRegion)})
			sts := sts.New(sess)

			// Set up a role provider and try to use it to download some data
			roleProvider := stscreds.NewWebIdentityRoleProviderWithOptions(sts, tc.roleArn, awsSessionName, stscreds.FetchTokenPath(tokenPath))
			_, err = fetchBlobFromS3(sess, roleProvider)
			if err == nil && tc.wantFailure {
				t.Fatalf("expected to get err when trying to assume role + download from blob")
			}
			if err != nil && !tc.wantFailure {
				if !tc.wantFailure {
					t.Fatalf("failed to download blob from S3: %v", err)
				}
			}
		})
	}
}

func writeTokenToPath(token string, tokenPath string) {
	os.WriteFile(tokenPath, []byte(token), 0644)
}

func fetchBlobFromS3(s *session.Session, provider credentials.Provider) ([]byte, error) {

	client := s3.New(s, &aws.Config{
		Credentials: credentials.NewCredentials(provider),
	})

	input := &s3.GetObjectInput{
		Bucket: aws.String(s3Bucket),
		Key:    aws.String(s3String),
	}
	result, err := client.GetObject(input)
	if err != nil {
		return nil, err
	}

	buf := new(strings.Builder)
	_, err = io.Copy(buf, result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read from result response body: %w", err)
	}

	return []byte(buf.String()), nil
}
