Confidetial Space Attested TLS Example


The server code stands up an HTTP server, listens for a request, authenticates itself and then waits for the data over the TLS connection.

The client performs the opposite.

The server code exposes the 8081 port to be able to listen to requests. See the Dockerfile for more information.

Both client + server redirect their logging to allow you to see the requests occurring.
