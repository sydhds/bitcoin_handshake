use anyhow::anyhow;
// use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedRead, FramedWrite};

use crate::codec::{MessageDecoder, MessageEncoder};
use bth_message::message::{Message, MessageRaw};

/// Receive a Message from network
pub async fn recv_message<R>(reader: &mut R) -> anyhow::Result<MessageRaw>
where
    R: AsyncRead + Send + Unpin + 'static,
{
    let codec = MessageDecoder::new();
    let mut fr = FramedRead::new(reader, codec);
    if let Ok(msg_raw) = fr.next().await.ok_or(anyhow!("Cannot read frame"))? {
        return Ok(msg_raw);
    }

    Err(anyhow!("Unable to recv msg"))
}

/// Send a Message through the network
pub async fn send_message<W>(writer: &mut W, msg: Message) -> anyhow::Result<()>
where
    W: AsyncWrite + Send + Unpin + 'static,
{
    let codec = MessageEncoder::new();
    let mut fw = FramedWrite::new(writer, codec);
    fw.send(msg).await.map_err(|e| anyhow!(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
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

                let (mut reader, mut writer) = socket.into_split();

                tokio::io::stdout()
                    .write_all(b"Server waiting...\n")
                    .await?;
                let msg = recv_message(&mut reader).await?;

                tokio::io::stdout()
                    .write_all(format!("Server received: {:?}...\n", msg).as_bytes())
                    .await?;

                tokio::io::stdout()
                    .write_all(b"Server sending message...\n")
                    .await?;

                let msg_to_send = Message::new();
                send_message(&mut writer, msg_to_send).await?;

                return Ok::<(), anyhow::Error>(());
            }
        });

        // dummy client
        let coro2 = tokio::spawn(async move {
            let socket = TcpStream::connect(&addr[..]).await?;
            let (mut reader, mut writer) = socket.into_split();

            let msg = Message::new();
            tokio::io::stdout()
                .write_all(b"Client sending msg...\n")
                .await?;

            send_message(&mut writer, msg).await?;

            tokio::io::stdout()
                .write_all(b"Client waiting...\n")
                .await?;
            let msg_received = recv_message(&mut reader).await?;

            println!("msg received: {:?}", msg_received);

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
