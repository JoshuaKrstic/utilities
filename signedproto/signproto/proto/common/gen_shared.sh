#!/bin/bash

protoc \
    -I. \
    --go_out=../gen/common \
    --go_opt=module=josh.com/rimsign/proto/gen/common \
    --experimental_allow_proto3_optional shared.proto
