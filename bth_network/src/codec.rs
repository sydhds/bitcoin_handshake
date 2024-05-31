use anyhow::anyhow;
use std::error::Error;
use tokio_util::bytes::{Buf, BufMut, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

use bth_message::message::{Message, MessageDeserializer, MessageRaw, MessageSerializer};
use bth_message::serialization::{Deserializer, Serializer};

pub struct MessageEncoder {
    message_serializer: MessageSerializer,
}

impl MessageEncoder {
    pub(crate) fn new() -> Self {
        Self {
            message_serializer: MessageSerializer::new(),
        }
    }
}

impl Encoder<Message> for MessageEncoder {
    type Error = Box<dyn Error>;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.message_serializer.serialize(&item, dst)?;
        // .map_err(|e| anyhow!(e));
        Ok(())
    }
}

pub struct MessageDecoder {
    message_raw_deserializer: MessageDeserializer,
}

impl MessageDecoder {
    pub fn new() -> Self {
        Self {
            message_raw_deserializer: MessageDeserializer::new(),
        }
    }
}

const MAX_PAYLOAD_SIZE: usize = 8 * 1024 * 1024;

impl Decoder for MessageDecoder {
    type Item = MessageRaw;
    type Error = Box<dyn Error>;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Need magic (4 bytes) + command (12 bytes) + len (4 bytes)
        let index_start_length = 4 + 12;
        let index_end_length = index_start_length + 4;
        if src.len() < index_end_length {
            // Not enough data to read length marker.
            return Ok(None);
        }

        // Read length marker.
        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[index_start_length..index_end_length]);
        let payload_length = u32::from_le_bytes(length_bytes) as usize;

        if payload_length > MAX_PAYLOAD_SIZE {
            // return Err(std::io::Error::new(
            //     std::io::ErrorKind::InvalidData,
            //
            // ));
            return Err(format!("Frame of payload length {} is too large.", payload_length).into());
        }

        // let expected_length = 4 + 12 + 4 + 4 + payload_length;
        let expected_length = index_end_length + 4 + payload_length;

        if src.len() < expected_length {
            src.reserve(expected_length - src.len());
            return Ok(None);
        }

        let data = src[..expected_length].to_vec();
        src.advance(expected_length);

        let (_content, message_raw) = self
            .message_raw_deserializer
            .deserialize(data.as_ref())
            .map_err(|e| e.to_string())?;

        Ok(Some(message_raw))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bth_message::message::MessagePayloadDeserializer;
    use std::error::Error;

    #[test]
    fn test_verack_encode_then_decode() -> Result<(), Box<dyn Error>> {
        let message = Message::new();
        let msg_original = message.clone();
        // encode
        let mut buf = BytesMut::new();
        let mut codec_encoder = MessageEncoder::new();
        codec_encoder.encode(message, &mut buf).unwrap();

        // decode
        let mut codec_decoder = MessageDecoder::new();
        let message_raw_decoded = codec_decoder.decode(&mut buf).unwrap().unwrap();

        let der2 = MessagePayloadDeserializer::new();
        let message_decoded = Message::try_from((message_raw_decoded, der2)).unwrap();
        assert_eq!(msg_original, message_decoded);

        Ok(())
    }
}
