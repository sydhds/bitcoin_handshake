mod cli;

use clap::Parser;

use crate::cli::Cli;
use bth_message::message::{Message, MessageCommand, MessageMagic, MessagePayload};
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

    // Init our connection with a bitcoin node - doing the bitcoin handshake
    let mut conn = BitcoinNode::try_connect(cli.ip, cli.port).await?;
    // Send msg ping
    conn.try_send(msg_ping).await?;

    // TODO: wait for Pong helper with timeout?
    let mut count = 10;
    while count > 0 {
        let message_received_ = conn.try_recv().await;
        println!("message received: {:?}", message_received_);
        if let Ok(message_received) = message_received_ {
            if message_received.command == MessageCommand::Pong {
                println!("Received pong - exiting...");
                break;
            }
        }
        count -= 1;
    }

    Ok(())
}
