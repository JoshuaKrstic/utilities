#!/bin/bash

protoc \
    -I. \
    -I.. \
    --go_out=../gen/google_tdx_tcb \
    --go_opt=module=josh.com/rimsign/proto/gen/google_tdx_tcb \
    --experimental_allow_proto3_optional google_tdx_tcb.proto
