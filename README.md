# IOTA C Client

This is an IOTA client library written in C; it can be used to connect to a user-supplied IOTA node that exports the HTTP IRI API, and can do things such as getting the current balance, transferring IOTAs, or simply sending 0-value transactions to the tangle.

It can connect to IOTA nodes using either HTTP or HTTPS.

Tested with ESP32 using the ESP-IDF (this library implements an ESP-IDF component).

## Installation

```
$ git clone --recursive https://github.com/francescolavra/iota-c-client.git
```
