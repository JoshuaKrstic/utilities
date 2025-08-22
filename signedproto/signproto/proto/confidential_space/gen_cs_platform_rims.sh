#!/bin/bash

protoc \
    -I. \
    -I.. \
    -I$(go list -m -f "{{.Dir}}" github.com/google/go-tpm-tools) \
    -I$(go list -m -f "{{.Dir}}" github.com/google/go-tpm-tools)/proto \
    -I$(go list -m -f "{{.Dir}}" github.com/google/go-sev-guest) \
    -I$(go list -m -f "{{.Dir}}" github.com/google/go-tdx-guest) \
    --go_out=../gen/confidential_space_platform_rims \
    --go_opt=module=josh.com/rimsign/proto/gen/confidential_space_platform_rims \
    --experimental_allow_proto3_optional confidential_space_platform_rims.proto