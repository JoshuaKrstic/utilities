package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/golang-jwt/jwt/v4"
)

func getTokenFromLauncher() string {

	tokenbytes := []byte("eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1IiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL21lYWwuY29ycCIsImV4cCI6MTcwOTk0MDMyNiwiaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS90YWdzIjp7InByaW5jaXBhbF90YWdzIjp7ImNvbmZpZGVudGlhbF9zcGFjZS5zdXBwb3J0X2F0dHJpYnV0ZXMiOlsiTEFURVNUPVNUQUJMRT1VU0FCTEUiXSwiY29udGFpbmVyLmltYWdlX2RpZ2VzdCI6WyJzaGEyNTY6NjY3YjdjYzk0MDdmN2Q5OTQ5ZDQzZmQ1MWRkZTJhNWI2NmRiOWI2OTVlZjViZmU1MjVjZjg1NzZkNTRmZmFhOSJdLCJkYmdzdGF0IjpbImVuYWJsZWQiXSwiaHdtb2RlbCI6WyJHQ1BfQU1EX1NFViJdLCJzZWNib290IjpbInRydWUiXSwic3duYW1lIjpbIkNPTkZJREVOVElBTF9TUEFDRSJdLCJzd3ZlcnNpb24iOlsiMjMwOTAyIl19fSwiaWF0IjoxNzA5NzU3ODE2LCJpc3MiOiJodHRwczovL3N0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYXdzX3Rva2VuX2J1Y2tldC9hd3NfdG9rZW5fdGVzdGluZyIsIm5iZiI6MTcwOTc1NzgxNiwic3ViIjoidGhpc2lzYXRlc3RzdWIifQ.Cmk8CqpfORmrJIVJbBVBd6M27SPPOxNNVJK8k3yoJR4irT42exohG-G-CMIfY8sAaqaez1VUOfc1xwjTO4KBpdgffAn1ZMUXwgAWUg2YiFk_NlqpcCKtEYybwun4JYfHAru70uSlc7Uv9jMTBNsUrHCl8C6rxi_7EV_hj2Qs0geuhq63Cjo-16WetsS7wguVAqO5Z_cQI1xx9Vfc8wXGg-b0x_veclGxVJJmVGZFba1Mbxhh6SevtK9zxKmdMMzlrgHKRsr5GDtn8T9IwOeg-SIW8wN6U2OBjiuIpVMlzxQVLy0ot-agX0CI9miCEoEFKA_h0doiznKxZdgQuLzslg")
	mapClaims := jwt.MapClaims{}
	_, _, err := jwt.NewParser().ParseUnverified(string(tokenbytes), mapClaims)
	if err != nil {
		panic(err)
	}
	claimsString, err := json.MarshalIndent(mapClaims, "", "  ")
	if err != nil {
		panic(err)
	}
	fmt.Printf("Token received from Confidential Space: %v\n\n", string(claimsString))

	return string(tokenbytes)
}

func writeTokenToPath(token string, tokenPath string) {
	os.WriteFile(tokenPath, []byte(token), 0644)
}

func fetchBlobFromS3(s *session.Session, provider credentials.Provider) ([]byte, error) {
	myBucket := "corporation-corp-employee-data"
	myString := "ciphertext"

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

func handleDecryptError(err error) {
	if aerr, ok := err.(awserr.Error); ok {
		switch aerr.Code() {
		case kms.ErrCodeNotFoundException:
			fmt.Println(kms.ErrCodeNotFoundException, aerr.Error())
		case kms.ErrCodeDisabledException:
			fmt.Println(kms.ErrCodeDisabledException, aerr.Error())
		case kms.ErrCodeInvalidCiphertextException:
			fmt.Println(kms.ErrCodeInvalidCiphertextException, aerr.Error())
		case kms.ErrCodeKeyUnavailableException:
			fmt.Println(kms.ErrCodeKeyUnavailableException, aerr.Error())
		case kms.ErrCodeIncorrectKeyException:
			fmt.Println(kms.ErrCodeIncorrectKeyException, aerr.Error())
		case kms.ErrCodeInvalidKeyUsageException:
			fmt.Println(kms.ErrCodeInvalidKeyUsageException, aerr.Error())
		case kms.ErrCodeDependencyTimeoutException:
			fmt.Println(kms.ErrCodeDependencyTimeoutException, aerr.Error())
		case kms.ErrCodeInvalidGrantTokenException:
			fmt.Println(kms.ErrCodeInvalidGrantTokenException, aerr.Error())
		case kms.ErrCodeInternalException:
			fmt.Println(kms.ErrCodeInternalException, aerr.Error())
		case kms.ErrCodeInvalidStateException:
			fmt.Println(kms.ErrCodeInvalidStateException, aerr.Error())
		case kms.ErrCodeDryRunOperationException:
			fmt.Println(kms.ErrCodeDryRunOperationException, aerr.Error())
		default:
			fmt.Println(aerr.Error())
		}
	} else {
		// Print the error, cast err to awserr.Error to get the Code and
		// Message from an error.
		fmt.Println(err.Error())
	}
}

func main() {
	tokenPath := "./token"

	token := getTokenFromLauncher()
	writeTokenToPath(token, tokenPath)

	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	sts := sts.New(sess)
	roleARN := "arn:aws:iam::232510754029:role/mealcorp-keyaccess"

	roleProvider := stscreds.NewWebIdentityRoleProviderWithOptions(sts, roleARN, "mealcorp", stscreds.FetchTokenPath(tokenPath))

	// Download data from AWS
	blobFromS3, err := fetchBlobFromS3(sess, roleProvider)
	if err != nil {
		fmt.Printf("failed to fetch blob from S3: %v\n", err)
		return
	}

	svc := kms.New(sess, &aws.Config{
		Credentials: credentials.NewCredentials(roleProvider),
	})
	input := &kms.DecryptInput{
		// KeyId is optional for symmetric key decryption, but is a best practice
		KeyId:          aws.String("arn:aws:kms:us-east-2:232510754029:key/32e9c399-58ef-4b89-96ec-46473d53cd6f"),
		CiphertextBlob: []byte(blobFromS3),
	}

	result, err := svc.Decrypt(input)
	if err != nil {
		handleDecryptError(err)
		return
	}

	fmt.Printf("Decrypt Succeeded: %v\n", result)
	fmt.Printf("%v\n", string(result.Plaintext))

	fmt.Println("\n\nMeals have been ordered for Bob, Alice, and Josh!\n\n")
}
