use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::anyhow;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::try_join;
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::codec::{MessageDecoder, MessageEncoder};
use bth_message::message::{Message, MessageMagic, MessagePayload, MessageRaw};
use bth_message::version::Version;
use log::debug;

/// Receive a Message from network
pub async fn recv_message2<R>(fr: &mut FramedRead<R, MessageDecoder>) -> anyhow::Result<MessageRaw>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    if let Ok(msg_raw) = fr.next().await.ok_or(anyhow!("Cannot read frame"))? {
        return Ok(msg_raw);
    }

    Err(anyhow!("Unable to recv msg"))
}

/// Send a Message through the network
pub async fn send_message2<W>(
    fw: &mut FramedWrite<W, MessageEncoder>,
    msg: Message,
) -> anyhow::Result<()>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    fw.send(msg).await.map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}

pub struct BitcoinNode {
    fr: FramedRead<ReadHalf<TcpStream>, MessageDecoder>,
    fw: FramedWrite<WriteHalf<TcpStream>, MessageEncoder>,
}

impl BitcoinNode {
    pub async fn try_connect(ip_addr: IpAddr, port: u16) -> Result<Self, anyhow::Error> {
        // Setup msg version & msg verack
        let nonce: u64 = rand::random();
        let start = SystemTime::now();
        let since_the_epoch = start
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards");
        let version = Version::new(ip_addr, port, nonce, since_the_epoch.as_secs() as i64);
        let msg_version = Message::from((MessageMagic::Main, MessagePayload::Version(version)));
        let msg_verack = Message::from((MessageMagic::Main, MessagePayload::Verack));

        let codec_dec = MessageDecoder::new();
        let codec_enc = MessageEncoder::new();

        let addr = SocketAddr::new(ip_addr, port);

        // Connect
        let socket = TcpStream::connect(addr).await?;
        let (reader, writer) = tokio::io::split(socket);

        let mut fr = FramedRead::new(reader, codec_dec);
        let mut fw = FramedWrite::new(writer, codec_enc);

        // Exchange version messages
        let (_, msg_received) =
            try_join!(send_message2(&mut fw, msg_version), recv_message2(&mut fr))?;

        debug!("handshake - msg_received: {:?}", msg_received);

        // Exchange verack messages
        let (_, msg_received) =
            try_join!(send_message2(&mut fw, msg_verack), recv_message2(&mut fr))?;

        debug!("verack - msg_received 2: {:?}", msg_received);

        Ok(Self { fr, fw })
    }

    pub async fn try_send(&mut self, message: Message) -> Result<(), anyhow::Error> {
        send_message2(&mut self.fw, message).await
    }

    pub async fn try_recv(&mut self) -> Result<MessageRaw, anyhow::Error> {
        recv_message2(&mut self.fr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bth_message::message::MessageCommand;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn network_send_receive() -> anyhow::Result<()> {
        let addr = "127.0.0.1:4242";

        // simple tcp server (sequential read & write)
        let coro1 = tokio::spawn(async move {
            let listener = TcpListener::bind(addr).await?;

            tokio::io::stdout()
                .write_all(b"Server listening...\n")
                .await?;
            loop {
                let (socket, _addr) = listener.accept().await?;
                socket.writable().await?;

                let (reader, writer) = tokio::io::split(socket);
                let mut fr = FramedRead::new(reader, MessageDecoder::new());
                let mut fw = FramedWrite::new(writer, MessageEncoder::new());

                tokio::io::stdout()
                    .write_all(b"Server waiting...\n")
                    .await?;
                let msg_received = recv_message2(&mut fr).await?;

                tokio::io::stdout()
                    .write_all(format!("Server received: {:?}...\n", msg_received).as_bytes())
                    .await?;
                assert_eq!(msg_received.command, MessageCommand::Verack);

                tokio::io::stdout()
                    .write_all(b"Server sending message...\n")
                    .await?;

                let msg_to_send = Message::from((MessageMagic::Main, MessagePayload::Verack));
                send_message2(&mut fw, msg_to_send).await?;

                return Ok::<(), anyhow::Error>(());
            }
        });

        // dummy client
        let coro2 = tokio::spawn(async move {
            let socket = TcpStream::connect(&addr[..]).await?;
            let (reader, writer) = tokio::io::split(socket);
            let mut fr = FramedRead::new(reader, MessageDecoder::new());
            let mut fw = FramedWrite::new(writer, MessageEncoder::new());

            let msg = Message::from((MessageMagic::Main, MessagePayload::Verack));
            tokio::io::stdout()
                .write_all(b"Client sending msg...\n")
                .await?;

            send_message2(&mut fw, msg).await?;

            tokio::io::stdout()
                .write_all(b"Client waiting...\n")
                .await?;
            let msg_received = recv_message2(&mut fr).await?;

            // println!("msg received: {:?}", msg_received);
            tokio::io::stdout()
                .write_all(format!("Client - msg received: {:?}", msg_received).as_bytes())
                .await?;
            assert_eq!(msg_received.command, MessageCommand::Verack);

            tokio::io::stdout()
                .write_all(format!("Client received: {:?}...\n", msg_received).as_bytes())
                .await?;

            Ok::<(), anyhow::Error>(())
        });

        let (res1, res2) = tokio::join!(coro1, coro2);

        // More debug
        println!("res 1: {:?}", res1);
        println!("res 2: {:?}", res2);

        res1??;
        res2??;
        Ok(())
    }
}
