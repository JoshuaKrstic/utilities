#!/bin/bash

PRIVATE_KEY_FILE="mykey.pem"
PUBLIC_KEY_FILE="mykey.pub"

echo "Generating a 4096-bit RSA private key..."
openssl genrsa -out "$PRIVATE_KEY_FILE" 4096

echo "Extracting public key from the private key..."
openssl rsa -in "$PRIVATE_KEY_FILE" -pubout -out "$PUBLIC_KEY_FILE"

echo "Done"