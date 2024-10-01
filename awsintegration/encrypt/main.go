package main

import (
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cognitoidentityprovider"

	//"github.com/aws/aws-sdk-go/config"
	"github.com/aws/aws-sdk-go/service/kms"
	"github.com/aws/aws-sdk-go/service/sts"
)

// Call aws.Encrypt to encrypt the meal preference text
// Token is exchanged with AWS.
//   - golang library? Or just cmdline and pass it in?
// Call AWS decrypt with the access key provided by the call to AWS IAM
// Print out the results. Failure results in noeat

func getTokenFromLauncher() string {
	// Todo - Ask the Launcher for a custom token
	// Todo - Update the launcher to return this token
	return "eyJhbGciOiJSUzI1NiIsImtpZCI6IjEyMzQ1IiwidHlwIjoiSldUIn0.eyJhdWQiOiJodHRwczovL21lYWwuY29ycCIsImV4cCI6MTcyNTU2MDk3OCwiZ2NlLnpvbmUiOiJub3J0aGFtZXJpY2Etbm9ydGhlYXN0Mi1iIiwiaHR0cHM6Ly9hd3MuYW1hem9uLmNvbS90YWdzIjp7InByaW5jaXBhbF90YWdzIjp7ImNvbmZpZGVudGlhbF9zcGFjZS5zdXBwb3J0X2F0dHJpYnV0ZXMiOlsiTEFURVNUPVNUQUJMRT1VU0FCTEU9Il0sImRiZ3N0YXQiOlsiZGlzYWJsZWQtc2luY2UtYm9vdCJdLCJnY2UucHJvamVjdF9pZCI6WyJ0ZXN0LXByb2plY3QtcGFkZGVkLXRvLTMwLWNoYXIiXSwiZ2NlLnpvbmUiOlsibm9ydGhhbWVyaWNhLW5vcnRoZWFzdDItYiJdLCJod21vZGVsIjpbIkdDUF9BTURfU0VWIl0sInNpZ25hdHVyZS1rZXlfaWQtQUIiOlsiRUNEU0FfUDI1Nl9TSEEyNTY6VGhpc0lzRmluZ2VyUHJpbnRBLTdjYTBlM2U3ODNiMmJkNWFjYmZlYTZjODNkZDgyOTcxYTQxNTBkZjViMjVmOSJdLCJzaWduYXR1cmUta2V5X2lkLUJDIjpbIkVDRFNBX1AyNTZfU0hBMjU2OlRoaXNJc0ZpbmdlclByaW50Qi03Y2EwZTNlNzgzYjJiZDVhY2JmZWE2YzgzZGQ4Mjk3MWE0MTUwZGY1YjI1ZjkiXSwic3duYW1lIjpbIkNPTkZJREVOVElBTF9TUEFDRSJdLCJzd3ZlcnNpb24iOlsiMjMwOTAyIl19LCJyZXF1ZXN0X3RhZ3MiOnt9fSwiaWF0IjoxNzI1NTU3Mzc4LCJpc3MiOiJodHRwczovL3N0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYXdzX3Rva2VuX2J1Y2tldC9hd3NfdG9rZW5fdGVzdGluZyIsInN1YiI6InRoaXNpc2F0ZXN0c3ViIiwic3VibW9kcyI6eyJjb250YWluZXIiOnsiaW1hZ2VfZGlnZXQiOiJhYmMxMjMifX19.Bwsb_9nlya6WFHG6rvYlmEXtDq5kC8HDDqrB96NWRJfnAvSCJH4Fv2WIzqmkx-o3NiSHsmKl94gv8uIU9cHBD5Ps5C7doRydDY4pMPoxO1SKQnrTuvrdYNY-BJ_AT-V92XBHHVSMOv79KPs4wGNIc-txdAmLnT-Z9H6BwqDrLolCMgMwaF6Pi1J-1bBZ2EDX-bOhMBZYwNyF3JB-_JpeuP8cmPIOXRZ-XKEevU_lOWZnu6aJJE70jPcrHCE9OQTWBaobAEhmy6gKFDUbd7YZb6IigHM9Sf5_HAxJeE_hB0N5-rHUhKT5PpTjBUBW_BQscs8Vld4Qj1r8gPXTVyab9A"
}

func writeTokenToPath(token string, tokenPath string) {
	os.WriteFile(tokenPath, []byte(token), 0644)
}

func main() {
	tokenPath := "./token"

	token := getTokenFromLauncher()
	writeTokenToPath(token, tokenPath)

	// Get Creds from AWS
	//config, err := config.LoadDefaultConfig(context.TODO())
	// if err != nil {
	// 	log.Fatal(err)
	// }

	sess, _ := session.NewSession(&aws.Config{
		Region: aws.String("us-east-2")})
	sts := sts.New(sess)
	roleARN := "arn:aws:iam::232510754029:role/meal-corp-role"

	//roleProvider := stscreds.NewWebIdentityRoleProviderWithOptions(sts, roleARN, "gosession", stscreds.FetchTokenPath(tokenPath))
	cognitoProvider := cognitoidentityprovider.New(sess)
	idpArn := "arn:aws:cognito-identity:us-east-2:232510754029:identitypool/us-east-2:78a7198a-b71b-4d4c-856b-863cbc8accea"
	input := cognitoidentityprovider.GetIdentityProviderByIdentifierInput{
		IdpIdentifier: &idpArn,
	}
	identityProvider, err := cognitoProvider.GetIdentityProviderByIdentifier(&input)
	if err != nil {
		panic("Failed to get identityProvider from GetIdentityProviderByIdentifier")
	}

	identityProvider.IdentityProvider.

		// Call Decrypt with Creds
		//blobFromGCS := fetchBlobFromGCS()

		data, _ := os.ReadFile("./data")

	svc := kms.New(sess, &aws.Config{
		Credentials: credentials.NewCredentials(cognitoProvider),
	})
	input := &kms.EncryptInput{
		KeyId:     aws.String("arn:aws:kms:us-east-2:232510754029:key/8671ab52-d4b4-4181-81fd-5dc07bec9a96"),
		Plaintext: data,
	}
	result, err := svc.Encrypt(input)
	if err != nil {
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
		return
	}

	fmt.Printf("Encrypt Succeeded: %v\n", result)

	os.WriteFile("./ciphertext", result.CiphertextBlob, os.ModeAppend)
}
