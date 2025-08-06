package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	rimproto "josh.com/rimsign/proto/confidential_space_platform_rims"
)

const (
	leafCertPath       = "leafCertPath"
	rootCertPath       = "rootCertPath"
	privateKeyPathFlag = "privateKeyPath"
	textprotoPathFlag  = "textprotoPath"
	outputPathFlag     = "outputPath"

	outputFilename = "confidential_space_platform_rims.textproto"
)

// signDataPSS takes a byte slice and a private key, and returns a signature
// using the RSA-PSS scheme with SHA-256.
func signDataPSS(data []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	hashed := sha256.Sum256(data)

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return signature, nil
}

func parsePrivateKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	// Read and parse private key
	privKeyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	blockPriv, _ := pem.Decode(privKeyBytes)
	if blockPriv == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(blockPriv.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey.(*rsa.PrivateKey), nil
}

func imageDbTextProtoToBinary(filePath string) (*rimproto.ImageDatabase, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read text proto file at path %s: %w", filePath, err)
	}

	// Unmarshal the textproto
	imageDbRim := rimproto.ImageDatabase{}
	err = prototext.Unmarshal(data, &imageDbRim)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal text proto: %w", err)
	}

	// Marshal the proto into a binary format
	return &imageDbRim, nil
}

func generateWrapperBinProto(rimProto *rimproto.ImageDatabase, leafCert []byte, rootCert []byte) ([]byte, error) {
	// Expect a PEM leaf cert
	block, _ := pem.Decode(leafCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode leaf certificate PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}
	wrapperProto := &rimproto.ConfidentialSpacePlatformRims{
		ImageDatabase: rimProto,
		Timestamp:     timestamppb.Now(),
		Exp:           timestamppb.New(time.Now().Add(60 * 25 * time.Hour)), // 60 day expiration
		Cert:          leaf.Raw,
		CaBundle:      rootCert,
	}

	return proto.Marshal(wrapperProto)
}

func generateRimBinProto(wrapperBin []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	signature, err := signDataPSS(wrapperBin, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign wrapper binary: %w", err)
	}
	log.Println("Successfully signed the wrapper binary proto")
	rim := &rimproto.CSImageGoldenMeasurement{
		ConfidentialSpacePlatformRims: wrapperBin,
		Signature:                     signature,
		SignatureAlgorithm:            rimproto.SignatureAlgorithm_ECDSA_P256_SHA256,
	}

	return proto.Marshal(rim)
}

func main() {
	privateKeyPath := flag.String(privateKeyPathFlag, ".", "File containing the private key that will be used to sign the serialized proto data")
	leafCertPath := flag.String(leafCertPath, ".", "File containing leaf cert corresponding to the private key used to sign")
	rootCertPath := flag.String(rootCertPath, ".", "File containing the root certificate that signed the leaf cert")
	textprotoPath := flag.String(textprotoPathFlag, ".", "File containing the serialized proto data to be signed")
	outputPath := flag.String(outputPathFlag, ".", "File path to write the signed RIM binary proto")
	flag.Parse()

	imageDb, err := imageDbTextProtoToBinary(*textprotoPath)
	if err != nil {
		log.Fatalf("Error parsing text proto: %v", err)
	}
	log.Println("Parsed image database text proto")

	leafCert, err := os.ReadFile(*leafCertPath)
	if err != nil {
		log.Fatalf("Error reading leaf certificate: %v", err)
	}
	log.Println("Read leaf certificate")

	rootCert, err := os.ReadFile(*rootCertPath)
	if err != nil {
		log.Fatalf("Error reading root certificate: %v", err)
	}
	log.Println("Read root certificate")

	wrapperBin, err := generateWrapperBinProto(imageDb, leafCert, rootCert)
	if err != nil {
		log.Fatalf("Error generating wrapper proto: %v", err)
	}
	log.Println("Generated the wrapper proto")

	privateKey, err := parsePrivateKeyFromFile(*privateKeyPath)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}
	log.Println("Read and parsed private key")

	rimProtoBin, err := generateRimBinProto(wrapperBin, privateKey)
	if err != nil {
		log.Fatalf("Error generating RIM proto: %v", err)
	}
	log.Println("Generated the RIM binary proto")

	err = os.WriteFile(filepath.Join(*outputPath, outputFilename), rimProtoBin, 0644)
	if err != nil {
		log.Fatalf("Error writing signed RIM binary proto to file: %v", err)
	}

	log.Printf("Generated and wrote signed RIM binary proto to %s", *outputPath)
}
