# Contruno, a TLS termination proxy as a MirageOS

<p align="center">
  <img src="https://github.com/dinosaure/contruno/blob/main/img/uno.jpg?raw=true">
</p>

`contruno` is a TLS termination proxy is a proxy server that acts as an
intermediary point between client and server applications, and is used to
establish TLS tunnels with let's encrypt certificates.

From a Git repository which contains TLS certificates and private keys
delivered by let's encrypt, the user is able launch into its private network a
simple HTTP server. `contruno` does the bridge between the client which
initiates a TLS tunnel with a specific certificate from the Git repository and
its HTTP server.

`contruno` handles expiration of certificates and do the let's encrypt
challenge (the HTTP challenge) when one of is expired. Then, it renegociates
current connections with the new certificate and save it (with its private key)
into the Git repository.

If `contruno` shutdowns, you can restart it and, from the same Git repository,
it will restart the TLS termination proxy with all current certificates.
