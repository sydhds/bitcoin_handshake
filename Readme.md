# Bitcoin handshake

## Protocol

Handshake description:

* https://en.bitcoin.it/wiki/Protocol_documentation
* https://en.bitcoin.it/wiki/Version_Handshake

## Run

* RUST_LOG=debug cargo run -- --ip 127.0.0.1 --port 8333
* RUST_LOG=debug cargo run -- --ip 188.215.62.122 -p 8333

Find bitcoin node ip address:

* https://bitnodes.io/

## Unit tests

* cargo test