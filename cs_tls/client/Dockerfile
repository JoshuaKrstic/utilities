# Build:
# GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o tls .
#
# Upload to an artifact registry
# gcloud builds submit --tag asia-east1-docker.pkg.dev/jkrstic-test-project/testing/tlsekm-client
#
# Deploy Confidential Space machine
# gcloud compute instances create --confidential-compute --shielded-secure-boot --maintenance-policy=TERMINATE --scopes=cloud-platform --zone=asia-east1-a --image-project=confidential-space-images --image-family=confidential-space --metadata ^~^tee-image-reference=asia-east1-docker.pkg.dev/jkrstic-test-project/testing/tlsekm:latest~tee-container-log-redirect=true tlstestvm
FROM alpine:latest

LABEL "tee.launch_policy.log_redirect"="always"

WORKDIR /test
COPY tls /test
ENTRYPOINT ["/test/tls"]