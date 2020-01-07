# IOTA C Client

This is an IOTA client library written in C; it can be used to connect to a user-supplied IOTA node that exports the HTTP IRI API, and can do things such as getting the current balance, transferring IOTAs, or simply sending 0-value transactions to the tangle.

It can connect to IOTA nodes using either HTTP or HTTPS.

Supported platforms:
* ESP8266 and ESP32 (this library implements an ESP-IDF component)
* CC3200
* CC3220

## Dependencies

* cJSON library (https://github.com/DaveGamble/cJSON) (for ESP8266 and ESP32, this library is already included in the ESP-IDF framework)

## Known Issues and Limitations

* CC3200: no support for Server Name Indication (SNI) TLS extension when doing a TLS handshake with HTTPS nodes; this means that the HTTPS node must send the correct server certificate (which must be verified by the CC3200 client using the root CA certificate stored in DER format at file path /cert/ca.pem) without relying on a server name indication from the client

## Installation

```
$ git clone --recursive https://github.com/francescolavra/iota-c-client.git
```
