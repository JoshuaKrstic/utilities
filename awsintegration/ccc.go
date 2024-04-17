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

	tokenbytes := []byte("eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1IiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL21lYWwuY29ycCIsImV4cCI6MTcxOTMxMDczMywiaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS90YWdzIjp7InByaW5jaXBhbF90YWdzIjp7ImNvbmZpZGVudGlhbF9zcGFjZS5zdXBwb3J0X2F0dHJpYnV0ZXMiOlsiTEFURVNUPVNUQUJMRT1VU0FCTEU9Il0sImNvbnRhaW5lci5pbWFnZV9kaWdlc3QiOlsic2hhMjU2Om5vdHRoZXNhbWVoYXNoOTk0OWQ0M2ZkNTFkZGUyYTViNjZkYjliNjk1ZWY1YmZlNTI1Y2Y4NTc2ZDU0ZmZhYTkiXSwiZ2NlLnpvbmUiOlsidXMtZWFzdDQtYyJdLCJod21vZGVsIjpbIkdDUF9BTURfU0VWIl0sInN3bmFtZSI6WyJDT05GSURFTlRJQUxfU1BBQ0UiXSwic3d2ZXJzaW9uIjpbIjIzMDkwMiJdfSwidHJhbnNpdGl2ZV90YWdfa2V5cyI6WyJjb250YWluZXIuaW1hZ2VfZGlnZXN0Il19LCJpYXQiOjE3MTMzMTA3MzMsImlzcyI6Imh0dHBzOi8vc3RvcmFnZS5nb29nbGVhcGlzLmNvbS9hd3NfdG9rZW5fYnVja2V0L21hbGljaW91c19hd3NfdG9rZW5fdGVzdGluZyIsInN1YiI6InRoaXNpc2F0ZXN0c3ViIn0.unxs1L5xzLuuS-TywauvtFxZiauwyoL4A1xqBJCbinkR6v-WP5HKmxeL2DMaBITzV_RxnSTNi05AHgCvH8HthDSQezP-v6BojrOYJjmrgYBHaCIQIlcy543zdA26Vu4P3x9H39Y3WXb9xpmGVJ84uEl3MC-KAwVeMt8Hj9wOfdkvz-g6w6EgqzcsXex8ayO8C6Yan6oiasc5yTj9iHFhMVDMul5lqlE1oMkLxKEvuSX_ILkrZPYPEHf8CUJFDUFasqZ-CwHLKMDLG6anO_rMySUupE_xfgGVE970-wgUACqYUwU_ivbM-kZuBo3g8hvsxrgxJ-FhKE8AskkacamjDA")
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
