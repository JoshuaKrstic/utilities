package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	certFileName       = "cert.pem"
	privateKeyPathFlag = "privateKeyPath"
	publicKeyPathFlag  = "publicKeyPath"

	certSerialNumber = 208808 // Make random if we end up caring
)

func parsePublicKeyFromFile(filePath string) (*rsa.PublicKey, error) {
	pubKeyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key file: %v", err)
	}
	blockPub, _ := pem.Decode(pubKeyBytes)
	if blockPub == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}
	pubKey, err := x509.ParsePKIXPublicKey(blockPub.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}
	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not an RSA key")
	}
	log.Println("Successfully read and parsed public key")

	return rsaPubKey, nil

}

func parsePrivateKeyFromFile(filePath string) (*rsa.PrivateKey, error) {
	// Read and parse private key
	privKeyBytes, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %v", err)
	}
	blockPriv, _ := pem.Decode(privKeyBytes)
	if blockPriv == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(blockPriv.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %v", err)
	}
	log.Println("Successfully read and parsed private key")

	return privateKey.(*rsa.PrivateKey), nil
}

func main() {
	privateKeyPath := flag.String(privateKeyPathFlag, ".", "File containing the mykey.pem private key")
	publicKeyPath := flag.String(publicKeyPathFlag, ".", "File containing the mykey.pub public key")
	flag.Parse()

	pubKeyDir, _ := filepath.Split(*publicKeyPath)

	rsaPubKey, err := parsePublicKeyFromFile(*publicKeyPath)
	if err != nil {
		log.Fatalf("Error parsing public key: %v", err)
	}

	privateKey, err := parsePrivateKeyFromFile(*privateKeyPath)
	if err != nil {
		log.Fatalf("Error parsing private key: %v", err)
	}

	// Generate a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(certSerialNumber),
		Subject: pkix.Name{
			Organization: []string{"ITA Testing"},
			CommonName:   "cs.ita.test",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 365 * 28), // Valid for 28 years
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		//ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageD, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	// Sign cert with private key
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, rsaPubKey, privateKey)
	if err != nil {
		log.Fatalf("Failed to create certificate: %v", err)
	}

	// Write to pem file
	err = os.WriteFile(filepath.Join(pubKeyDir, certFileName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), 0644)
	if err != nil {
		log.Fatalf("Failed to write %s: %v", certFileName, err)
	}

	log.Println("Cert created successfully and written to", certFileName)
}
