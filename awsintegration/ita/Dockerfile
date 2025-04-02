# If updated the workload source code or this Dockerfile, need to rebuild the image and regenerate the signature
# From current directory:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main .
# gcloud builds submit --tag asia-east1-docker.pkg.dev/jkrstic-test-project/testing/happypath:latest

FROM alpine

COPY main /

LABEL "tee.launch_policy.allow_env_override"="ALLOWED_OVERRIDE"
LABEL "tee.launch_policy.allow_cmd_override"="true"
LABEL "tee.launch_policy.log_redirect"="always"
LABEL "tee.launch_policy.allow_env_override"="custom_audience"
LABEL "tee.ita-api-key"="djE6MzliY2FhZDAtMjFjZi00NGJjLWFkY2MtMmNjNzFmMmIxNjVmOkdaMnRmdzZOY3ExanNiVHE3Rzg1OTRmbGwwbUhveVBmOXBUYkdSZno="
LABEL "tee.ita-region"="https://api-dev02-user10.ita-dev.adsdcsp.com"

ENTRYPOINT ["/main"]