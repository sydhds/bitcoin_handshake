mod cli;

use anyhow::anyhow;
use clap::Parser;
use log::{debug, info, warn};

use crate::cli::Cli;
use bth_message::message::{
    Message, MessageCommand, MessageMagic, MessagePayload, MessagePayloadDeserializer,
};
use bth_network::network::BitcoinNode;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // init logger
    env_logger::init();
    // Parse command line args
    let cli = Cli::parse();

    // Setup in advance msg ping
    let nonce: u64 = rand::random();
    let msg_ping = Message::from((MessageMagic::Main, MessagePayload::Ping(nonce)));
    let payload_der = MessagePayloadDeserializer::new();

    // Init our connection with a bitcoin node - doing the bitcoin handshake
    let mut conn = BitcoinNode::try_connect(cli.ip, cli.port).await?;
    info!("bitcoin handshake done, now sending ping message to check the connection...");
    // Send msg ping
    conn.try_send(msg_ping).await?;

    // TODO: wait for Pong helper with timeout?
    let mut count = 10;
    while count > 0 {
        let message_received_ = conn.try_recv().await;
        debug!("message received: {:?}", message_received_);
        if let Ok(message_received) = message_received_ {
            if message_received.command == MessageCommand::Pong {
                let pong_message = Message::try_from((message_received, payload_der))
                    .map_err(|e| anyhow!(e.to_string()))?;

                debug!("Pong message: {:?}", pong_message);

                if let MessagePayload::Pong(pong_nonce) = pong_message.payload {
                    if nonce == pong_nonce {
                        info!("Ping nonce == Pong nonce ✅🤩,🚀");
                    } else {
                        warn!("Ping nonce ({}) != pong ({}) are different ❌🥺😔", nonce, pong_nonce);
                    }
                }
                debug!("Received pong - exiting...");

                break;
            }
        }
        count -= 1;
    }

    Ok(())
}
