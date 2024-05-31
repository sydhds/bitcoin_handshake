use anyhow::anyhow;
// use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::codec::{FramedWrite, FramedRead};

use bth_message::message::{Message, MessageRaw};
use crate::codec::{MessageDecoder, MessageEncoder};


/// Receive a Message from network
pub async fn recv_message<R>(reader: &mut R) -> anyhow::Result<MessageRaw>
    where
        R: AsyncRead + Send + Unpin + 'static,
{
    // let codec = LengthDelimitedCodec::new();
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
    // let to_send = bson::to_vec(&msg)?;
    // let codec = LengthDelimitedCodec::new();
    let codec = MessageEncoder::new();
    let mut fw = FramedWrite::new(writer, codec);
    // fw.send(msg).await?;
    Ok(())
}