mod cli;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::Rng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
// use tokio::net::tcp::WriteHalf;
use tokio::io::{ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio_util::codec::{FramedRead, FramedWrite};
use bytes::BytesMut;
use tokio::try_join;
use clap::Parser;

use bth_message::version::Version;
use bth_message::serialization::{Deserializer, Serializer};
use bth_message::message::{
    Message, MessageCommand, MessageDeserializer, MessageMagic,
    MessagePayload, MessageRaw, MessageSerializer
};
use bth_network::network::{recv_message, recv_message2, send_message, BitcoinNode};
use bth_network::codec::MessageDecoder;
use crate::cli::Cli;

#[tokio::main]
async fn main() -> anyhow::Result<()> {

    env_logger::init();

    let cli = Cli::parse();

    // TODO: CLI
    // let ip_addr = IpAddr::from(Ipv4Addr::LOCALHOST);
    // let port = 8333;
    // let addr = format!("{}:{}", ip_addr, port);

    let nonce: u64 = rand::random();
    let msg_ping = Message::from((MessageMagic::Main, MessagePayload::Ping(nonce)));

    let mut conn = BitcoinNode::try_connect(cli.ip, cli.port).await?;
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

/*
async fn main2() -> anyhow::Result<()> {

    println!("Hello, world!");

    let ip_addr = IpAddr::from(Ipv4Addr::LOCALHOST);
    let port = 8333;
    let addr = format!("{}:{}", ip_addr, port);

    // let sock = TcpStream::connect(&addr).await?;
    // let (mut reader, mut writer) = sock.into_split();

    let mut rng = rand::thread_rng();
    let start = SystemTime::now();
    let since_the_epoch = start
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards");
    println!("{:?}", since_the_epoch);

    let version = Version::new(ip_addr, port, rng.gen::<u64>(), since_the_epoch.as_secs() as i64);
    println!("version: {:?}", version);

    let msg = Message::from((MessageMagic::Main, MessagePayload::Version(version)));
    // println!("msg: {:?}", msg);
    let msg_verack = Message::from((MessageMagic::Main, MessagePayload::Verack));

    let codec = MessageDecoder::new();

    // let msg = Message::new();

    // Send version message

    let mut socket = TcpStream::connect(&addr[..]).await?;
    // let (mut reader, mut writer) = socket.into_split();
    let (mut reader, mut writer) = tokio::io::split(socket);

    // tokio::io::stdout()
    //     .write_all(b"Sending msg version...\n")
    //     .await?;

    // send_message(&mut writer, msg).await?;
    // do_send(&mut writer, msg).await?;
    // // Receive version message
    // tokio::io::stdout()
    //     .write_all(b"Client waiting...\n")
    //     .await?;
    // // let msg_received = recv_message(&mut reader).await?;
    // let msg_received = do_recv(&mut reader).await?;
    // println!("msg_received: {:?}", msg_received);

    let (send_res, msg_raw) = try_join!(
        // do_send(&mut writer, msg),
        send_message(&mut writer, msg),
        do_recv(&mut reader)
        // recv_message(&mut reader)
    )?;

    println!("msg_raw: {:?}", msg_raw);
    println!("===");

    // send & recv verack

    let (_, msg_raw_verack) = try_join!(
        send_message(&mut writer, msg_verack),
        // FIXME: recv_message is wrong but do_recv is ok but why?
        // recv_message(&mut reader)
        do_recv(&mut reader)
    )?;

    println!("msg_raw_verack: {:?}", msg_raw_verack);

    let nonce: u64 = rand::random();
    let msg_ping = Message::from((MessageMagic::Main, MessagePayload::Ping(nonce)));

    println!("Sending ping with nonce: {} {:?}", nonce, u64::to_le_bytes(nonce));
    let mut fr = FramedRead::new(&mut reader, codec);
    send_message(&mut writer, msg_ping).await?;

    loop {
        // let recv_msg = recv_message(&mut reader).await?;
        let recv_msg = recv_message2(&mut fr).await?;
        // let recv_msg = do_recv(&mut reader).await?;
        println!("recv_msg: {:?}", recv_msg);
        if let MessageCommand::Pong = recv_msg.command {
            break;
        }
    }

    Ok(())
}
*/

async fn do_send(
    write: &mut WriteHalf<TcpStream>,
    message: Message,
) -> Result<(), anyhow::Error> {

    let ser = MessageSerializer::new();
    let mut buffer = BytesMut::new();
    ser.serialize(&message, &mut buffer).unwrap();

    write.write_all(buffer.as_ref()).await?;

    Ok(())
}

async fn do_recv(
    read: &mut ReadHalf<TcpStream>,
    // network: Network,
) -> Result<MessageRaw, anyhow::Error> {

    let mut buffer = [0; 24];
    read.read_exact(&mut buffer).await?;
    println!("read header: {:?}", buffer.to_vec());

    // let header = decode_header(&buffer)?;
    // header.verify_magic(network)?;

    let payload_len = u32::from_le_bytes(buffer[16..20].try_into().unwrap());
    println!("payload len: {}", payload_len);
    let mut payload = vec![0; payload_len as usize];
    read.read_exact(&mut payload).await?;
    println!("read payload...");

    // header.verify_checksum(&payload)?;
    // decode_payload(&header, &payload)

    let mut final_buf = Vec::new();
    final_buf.extend(buffer);
    final_buf.extend(payload);

    let der = MessageDeserializer::new();
    let (content, msg_raw_d) = der.deserialize(final_buf.as_slice()).unwrap();
    // assert!(content.is_empty());

    Ok(msg_raw_d)
}
