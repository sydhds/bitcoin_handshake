# Bitcoin handshake

A toy project that can connect to a Bitcoin node, send a ping and check for the received pong message.

No bitcoin crate have been used, the main dependencies are:
* [tokio](https://docs.rs/tokio/latest/tokio/) - async tcp networking
* [nom](https://docs.rs/nom/latest/nom/) - binary parsing (encode & decode Bitcoin message)
* [bitflags](https://docs.rs/bitflags/latest/bitflags/) - C bit flags handling

## Architecture

* bitcoin_node: bin
  * can connect to a Bitcoin node + ping/pong exchange
* bth_network: lib
  * Implement tokio_codec to send/receive message
  * use bth_message
* bth_message: lib
  * Bitcoin message (and other Bitcoin object) serialization & deserialization

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