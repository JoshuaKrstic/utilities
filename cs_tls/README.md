# Confidetial Space Attested TLS Example

This folder contains an example server built to run in Google Confidential Space that uses TLS to provide a secure, attested channel for distributing sensitve data.

This server is meant to be used with the client in the adjacent folder. The client is also built to run in Confidential Space but does not need to as it does not contain any dependencies on GCP or Confidential Space.

## Use Case

These applications demonstrate how a client can send sensitve information securely to a trusted, attested workload.
In this demonstration, the TLS EKM is used to prove that there is no MiTM of the connection.

## Flow

The server starts up an http server with TLS using the provided key and crt and waits for a connection. When it gets a connection to the listed endpoint, the server upgrades the connection to a websocket. Once the websocket upgrade has occurred, the server replies to the client with an attestation token generated with the EKM of the TLS connection as its nonce. This EKM is hashed and encoded into base64. The client validates this token by:

1. Checking that the token was signed by Google.
2. Regenerating the hashed EKM to compare to the one inside the eat_nonce of the token
3. Validating other claims, such as the container digest (not shown)

## Use

To try this out yourself simply deploy the server using the command in the comment block at the top of the Dockerfile in the server directory. You may need to build and upload the container to a separate artifact registry yourself.

Once the VM is started, you should see the output that contains the IP address of the server:

NAME           ZONE          MACHINE_TYPE    PREEMPTIBLE  INTERNAL_IP      EXTERNAL_IP     STATUS
tlsekm-client  asia-east1-a  n2d-standard-2               xxx.xxx.xxx.xxx  xxx.xxx.xxx.xx  RUNNING

Copy the external IP address.

Once the server is running, deploy the client by using the command in the comment block at the top of the Dockerfile in the client directory. Be sure to replace the IP address in the command with the once you just copied from the server deployment output.