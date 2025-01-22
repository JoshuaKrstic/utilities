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

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
)

const (
	// Token Request Constants
	socketPath    = "/run/container_launcher/teeserver.sock"
	tokenEndpoint = "http://localhost/v1/token"
	contentType   = "application/json"
	tokenPath     = "./token"
	tokenType     = "AWS_PRINCIPALTAGS"
	unixNetwork   = "unix"

	// AWS Config Constants
	roleARN        = "arn:aws:iam::232510754029:role/testingRoleForWebIdentity"
	awsKmsKeyID    = "arn:aws:kms:us-east-2:232510754029:key/32e9c399-58ef-4b89-96ec-46473d53cd6f"
	awsRegion      = "us-east-2"
	awsSessionName = "integration_test"
	myBucket       = "corporation-corp-employee-data"
	myString       = "ciphertext"

	// Workload Metadata Constants
	customAudienceVariable = "custom_audience"
	sigsVariable           = "container_sigs"
)

type tokenRequest struct {
	Audience         string           `json:"audience"`
	Nonces           []string         `json:"nonces"`
	TokenType        string           `json:"token_type"`
	TokenTypeOptions tokenTypeOptions `json:"aws_principal_tag_options"`
}

type tokenTypeOptions struct {
	AllowedPrincipalTags allowedPrincipalTags `json:"allowed_principal_tags"`
}

type allowedPrincipalTags struct {
	ContainerImageSignatures containerImageSignatures `json:"container_image_signatures"`
}

type containerImageSignatures struct {
	Key_ids []string `json:"key_ids"`
}

func getCustomTokenBytes(body string) (string, error) {
	httpClient := http.Client{
		Transport: &http.Transport{
			// Set the DialContext field to a function that creates
			// a new network connection to a Unix domain socket
			DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial(unixNetwork, socketPath)
			},
		},
	}

	resp, err := httpClient.Post(tokenEndpoint, contentType, strings.NewReader(body))
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

func fetchBlobFromS3(s *session.Session, provider credentials.Provider) ([]byte, error) {
	client := s3.New(s, &aws.Config{
		Credentials: credentials.NewCredentials(provider),
	})

	input := &s3.GetObjectInput{
		Bucket: aws.String(myBucket),
		Key:    aws.String(myString),
	}
	result, err := client.GetObject(input)
	if err != nil {
		return nil, err
	}

	buf := new(strings.Builder)
	n, err := io.Copy(buf, result.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read from result response body: %w", err)
	}

	fmt.Printf("downloaded blob from AWS at location '%v/%v'\n", myBucket, myString)
	fmt.Printf("blob length: %v bytes\n\n", n)

	return []byte(buf.String()), nil
}

func cleanup() {
	os.Remove(tokenPath)
}

func main() {
	audience, ok := os.LookupEnv(customAudienceVariable)
	if !ok {
		panic(fmt.Errorf("unable to find the custom audience variable. A variable with the name %v is required for this workload", customAudienceVariable))
	}

	rawSigs, ok := os.LookupEnv(sigsVariable)
	if !ok {
		panic(fmt.Errorf("unable to find the container image signature variable. A variable with the name %v is required for this workload", sigsVariable))
	}
	sigs := strings.Split(rawSigs, ",")

	// Get token from the launcher
	body := tokenRequest{
		Audience:  audience,
		TokenType: tokenType,
		TokenTypeOptions: tokenTypeOptions{
			AllowedPrincipalTags: allowedPrincipalTags{
				ContainerImageSignatures: containerImageSignatures{
					Key_ids: sigs,
				},
			},
		},
	}

	val, err := json.Marshal(body)
	if err != nil {
		err = fmt.Errorf("failed to marshal custom request into a request body. Attempted to marshal '%v', got err: %w", body, err)
		panic(err)
	}

	token, err := getCustomTokenBytes(string(val))
	if err != nil {
		panic(err)
	}
	fmt.Printf("Token recieved: %v", token)

	// AWS Module reads the token from a file
	os.WriteFile(tokenPath, []byte(token), 0644)

	// Assume the role with the token we just wrote to disk
	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String(awsRegion)})
	sts := sts.New(sess)
	roleProvider := stscreds.NewWebIdentityRoleProviderWithOptions(sts, roleARN, awsSessionName, stscreds.FetchTokenPath(tokenPath))

	// Download data from AWS
	blobFromS3, err := fetchBlobFromS3(sess, roleProvider)
	if err != nil {
		fmt.Printf("failed to fetch blob from S3: %v\n", err)
		return
	}

	// Call Decrypt
	svc := kms.New(sess, &aws.Config{
		Credentials: credentials.NewCredentials(roleProvider),
	})
	input := &kms.DecryptInput{
		// KeyId is optional for symmetric key decryption, but is a best practice
		KeyId:          aws.String(awsKmsKeyID),
		CiphertextBlob: []byte(blobFromS3),
	}

	result, err := svc.Decrypt(input)
	if err != nil {
		fmt.Printf("Decrypt Failed: %v\n", err)
		return
	}

	fmt.Printf("Decrypt Succeeded: %v\n", result)

	cleanup()
}
