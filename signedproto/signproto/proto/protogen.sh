#!/bin/bash

protoc \
  --proto_path=/Users/jkrstic/repos/utilities/signedproto/signproto \
  --proto_path=/Users/jkrstic/repos/go-tpm-tools/ \
  --proto_path=/Users/jkrstic/repos/go-tpm-tools/proto \
  --proto_path=/Users/jkrstic/repos/go-sev-guest/ \
  --proto_path=/Users/jkrstic/repos/go-tdx-guest/ \
  --go_out=./confidential_space_platform_rims \
confidential_space_platform_rims.proto