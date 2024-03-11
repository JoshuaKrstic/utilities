package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
)

func base64urlUIntEncode(i *big.Int) string {
	s := base64.RawURLEncoding.EncodeToString(i.Bytes())

	return s
}

func main() {
	privateKey, err := os.ReadFile("../mykey.pub")
	if err != nil {
		fmt.Printf("failed to read keyfile: %v\n", err)
		return
	}

	p, _ := pem.Decode([]byte(privateKey))
	if p == nil {
		fmt.Println("failed to decode key")
		return
	}

	key, err := x509.ParsePKIXPublicKey(p.Bytes)

	if err != nil {
		fmt.Printf("failed to parse public key from pem bytes: %v", err)
		return
	}

	if k, ok := key.(*rsa.PublicKey); ok {
		fmt.Printf("parse succeeded, key.E: %v\n key.N: %v\n", base64urlUIntEncode(big.NewInt(int64(k.E))), base64urlUIntEncode(k.N))
	} else {
		fmt.Printf("type assertion failed, this is not a rsa.PublicKey")
	}
}
