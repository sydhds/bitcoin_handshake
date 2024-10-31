use std::error::Error;

use bytes::{BufMut, BytesMut};
use nom::bytes::complete::take;
use nom::number::complete::{le_u32, le_u64};
use nom::AsBytes;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use sha2::{Digest, Sha256};

use crate::serialization::{Deserializer, NomError, Serializer};
use crate::version::{Version, VersionDeserializer, VersionSerializer};

#[derive(Debug, Clone, Copy, PartialEq, IntoPrimitive, TryFromPrimitive)]
#[repr(u32)]
pub enum MessageMagic {
    Main = 0xD9B4BEF9,
    Testnet = 0xDAB5BFFA,
    Testnet3 = 0x0709110B,
    Signet = 0x40CF030A,
    Namecoin = 0xFEB4BEF9,
}

#[derive(Clone, PartialEq, Debug)]
pub enum MessageCommand {
    Verack,
    Version,
    Ping,
    Pong,
    __Nonexhaustive,
}

const COMMAND_VERACK: [u8; 12] = [b'v', b'e', b'r', b'a', b'c', b'k', 0, 0, 0, 0, 0, 0];
const COMMAND_VERSION: [u8; 12] = [b'v', b'e', b'r', b's', b'i', b'o', b'n', 0, 0, 0, 0, 0];
const COMMAND_PING: [u8; 12] = [b'p', b'i', b'n', b'g', 0, 0, 0, 0, 0, 0, 0, 0];
const COMMAND_PONG: [u8; 12] = [b'p', b'o', b'n', b'g', 0, 0, 0, 0, 0, 0, 0, 0];
const COMMAND_OTHER: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

impl From<&MessageCommand> for [u8; 12] {
    fn from(value: &MessageCommand) -> Self {
        match value {
            MessageCommand::Verack => COMMAND_VERACK,
            MessageCommand::Version => COMMAND_VERSION,
            MessageCommand::Ping => COMMAND_PING,
            MessageCommand::Pong => COMMAND_PONG,
            MessageCommand::__Nonexhaustive => COMMAND_OTHER,
        }
    }
}

impl TryFrom<&[u8; 12]> for MessageCommand {
    type Error = &'static str;

    fn try_from(value: &[u8; 12]) -> Result<Self, Self::Error> {
        Ok(match value {
            v if *v == COMMAND_VERACK => MessageCommand::Verack,
            v if *v == COMMAND_VERSION => MessageCommand::Version,
            v if *v == COMMAND_PING => MessageCommand::Ping,
            v if *v == COMMAND_PONG => MessageCommand::Pong,
            _ => MessageCommand::__Nonexhaustive,
        })
    }
}

#[derive(Clone, PartialEq, Debug)]
pub enum MessagePayload {
    Verack,
    Version(Version),
    Ping(u64),
    Pong(u64),
    __Nonexhaustive,
}

#[derive(Clone)]
pub struct MessagePayloadDeserializer {
    version_deserializer: VersionDeserializer,
    command: Option<MessageCommand>,
}

impl MessagePayloadDeserializer {
    pub fn new() -> Self {
        Self {
            version_deserializer: VersionDeserializer::new(),
            command: None,
        }
    }
}

impl Default for MessagePayloadDeserializer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deserializer<MessagePayload> for MessagePayloadDeserializer {
    fn deserialize<'a>(
        &self,
        buffer: &'a [u8],
    ) -> Result<(&'a [u8], MessagePayload), Box<dyn Error + 'a>> {
        match self.command.as_ref().ok_or("command not set")? {
            MessageCommand::Verack => Ok((buffer, MessagePayload::Verack)),
            MessageCommand::Version => {
                let (content, version) = self.version_deserializer.deserialize(buffer)?;
                Ok((content, MessagePayload::Version(version)))
            }
            MessageCommand::Pong => {
                let (content, nonce) = le_u64::<_, NomError>(buffer)?;
                Ok((content, MessagePayload::Pong(nonce)))
            }
            MessageCommand::Ping => {
                let (content, nonce) = le_u64::<_, NomError>(buffer)?;
                Ok((content, MessagePayload::Ping(nonce)))
            }
            MessageCommand::__Nonexhaustive => Err("Unknown message command".into()),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct MessageRaw {
    /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown
    pub magic: MessageMagic,
    /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
    pub command: MessageCommand,
    /// Length of payload in number of bytes
    pub length: u32,
    /// First 4 bytes of sha256(sha256(payload))
    pub checksum: u32,
    /// The actual data
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
/// From <https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure>
pub struct Message {
    /// Magic value indicating message origin network, and used to seek to next message when stream state is unknown
    pub magic: MessageMagic,
    /// ASCII string identifying the packet content, NULL padded (non-NULL padding results in packet rejected)
    pub command: MessageCommand,
    /// The actual data
    pub payload: MessagePayload,
}

/*
impl Default for Message {
    fn default() -> Self {
        Self {

        }
    }
}
*/

/*
impl Message {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        // let command = "verack"
        //     .as_bytes()
        //     .iter()
        //     .cloned()
        //     .chain(std::iter::repeat(0))
        //     .take(12)
        //     .collect::<Vec<u8>>();
        let command = MessageCommand::Verack;
        // let payload: Vec<u8> = vec![];
        let payload = MessagePayload::Verack;

        // Checksum
        // let mut hasher1 = Sha256::new();
        // let mut hasher2 = Sha256::new();
        // hasher1.update(payload.as_bytes());
        // let hash1 = hasher1.finalize();
        // let hash2 = hasher2.update(hash1);

        // let mut payload_content = Vec::new();
        // payload.ser(&mut payload_content);
        // let checksum = Sha256::digest(Sha256::digest(payload_content));
        // println!("checksum: {:?}", checksum);

        Self {
            magic: MessageMagic::Main,
            command,
            // length: None,
            // checksum: None,
            payload,
        }
    }

    /*
    fn new_version(&self, version: &Version) {
    }
    */

    /*
    fn ser(&self, buffer: &mut Vec<u8>) {
        buffer.extend(u32::from(self.magic).to_le_bytes());
        buffer.extend(<[u8; 12]>::from(&self.command));
        buffer.extend(self.length.to_le_bytes());
        buffer.extend(self.checksum.to_le_bytes());
        self.payload.ser(buffer);
    }
    */

    // fn ser_buf<T>(&self, buffer: &mut T) where T: BufMut {
    //     // buffer.extend_ (u32::from(self.magic).to_le_bytes());
    //     buffer.put_u32_le(u32::from(self.magic));
    //     buffer.put(<[u8; 12]>::from(&self.command).as_slice());
    //     buffer.put_u32_le(self.length);
    //     buffer.put_u32_le(self.checksum);
    //     // self.payload.ser(buffer);
    // }

    // TODO?
    /*
    fn size_hint(&self) -> Option<usize> {
        match self.payload {
            MessagePayload::Verack => Some(0)
            MessagePayload::Version(_) => Some(4 + 12 + 4 + 4 + self.payload.size_hint());
            MessagePayload::__Nonexhaustive => {}
        }
    }
    */
}
*/

impl From<(MessageMagic, MessagePayload)> for Message {
    fn from((magic, payload): (MessageMagic, MessagePayload)) -> Self {
        let command = match &payload {
            MessagePayload::Verack => MessageCommand::Verack,
            MessagePayload::Version(_) => MessageCommand::Version,
            MessagePayload::Ping(_) => MessageCommand::Ping,
            MessagePayload::Pong(_) => MessageCommand::Pong,
            MessagePayload::__Nonexhaustive => MessageCommand::__Nonexhaustive,
        };

        Self {
            magic,
            command,
            payload,
        }
    }
}

impl TryFrom<(MessageRaw, MessagePayloadDeserializer)> for Message {
    type Error = Box<dyn Error>;

    fn try_from(
        (value, der): (MessageRaw, MessagePayloadDeserializer),
    ) -> Result<Self, Self::Error> {
        // verify checksum
        let checksum = Sha256::digest(Sha256::digest(value.payload.as_slice()));
        let checksum_start: &[u8; 4] = checksum[..4].try_into().unwrap();

        if value.checksum != u32::from_le_bytes(*checksum_start) {
            return Err("Invalid checksum".into());
        }

        let der2 = {
            let mut der_ = der.clone();
            der_.command = Some(value.command.clone());
            der_
        };

        let (rem, payload) = der2
            .deserialize(value.payload.as_bytes())
            .map_err(|e| e.to_string())?;

        if !rem.is_empty() {
            return Err("Remaining bytes after payload".into());
        }

        let message = Self {
            magic: value.magic,
            command: value.command,
            payload,
        };

        Ok(message)
    }
}

pub struct MessageSerializer {
    version_serializer: VersionSerializer,
}

impl MessageSerializer {
    pub fn new() -> Self {
        Self {
            version_serializer: VersionSerializer::new(),
        }
    }
}

impl Default for MessageSerializer {
    fn default() -> Self {
        Self::new()
    }
}

impl Serializer<Message> for MessageSerializer {
    fn serialize<B: BufMut>(&self, value: &Message, mut buffer: B) -> Result<(), Box<dyn Error>> {
        let mut payload_buffer = BytesMut::new();
        match value.payload {
            MessagePayload::Verack => {}
            MessagePayload::Version(ref version) => {
                self.version_serializer
                    .serialize(version, &mut payload_buffer)?;
            }
            MessagePayload::Ping(nonce) => {
                payload_buffer.put_u64_le(nonce);
            }
            MessagePayload::Pong(nonce) => {
                payload_buffer.put_u64_le(nonce);
            }
            MessagePayload::__Nonexhaustive => {}
        };

        buffer.put_u32_le(u32::from(value.magic));
        buffer.put((<[u8; 12]>::from(&value.command)).as_slice());
        buffer.put_u32_le(u32::try_from(payload_buffer.len())?);
        let checksum = Sha256::digest(Sha256::digest(payload_buffer.as_ref()));
        // TODO check checksum len
        let checksum_start: &[u8; 4] = checksum[..4].try_into().unwrap();
        buffer.put_u32_le(u32::from_le_bytes(*checksum_start));
        buffer.put(payload_buffer);

        Ok(())
    }
}

pub struct MessageDeserializer {}

impl MessageDeserializer {
    pub fn new() -> Self {
        Self {}
    }
}

impl Default for MessageDeserializer {
    fn default() -> Self {
        Self::new()
    }
}

impl Deserializer<MessageRaw> for MessageDeserializer {
    fn deserialize<'a>(
        &self,
        buffer: &'a [u8],
    ) -> Result<(&'a [u8], MessageRaw), Box<dyn Error + 'a>> {
        let (content, magic_) = le_u32::<_, NomError>(buffer)?;
        let magic = MessageMagic::try_from(magic_)?;

        let (content, command_slice) = take::<_, _, NomError>(12usize)(content)?;
        let command_bytes: &[u8; 12] = command_slice.try_into().unwrap();
        // println!("command bytes: {:?}", std::str::from_utf8(command_bytes));
        let command = MessageCommand::try_from(command_bytes)?;
        // println!("command: {:?}", command);

        let (content, length) = le_u32::<_, NomError>(content)?;
        let (content, checksum) = le_u32::<_, NomError>(content)?;

        // TODO limit length?
        let (content, payload) = take::<_, _, NomError>(length as usize)(content)?;

        if command == MessageCommand::Verack && !payload.is_empty() {
            return Err("Command verack but payload is not empty".into());
        }

        let message = MessageRaw {
            magic,
            command,
            length,
            checksum,
            payload: payload.to_vec(),
        };

        Ok((content, message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::AsBytes;

    // From https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    const EXPECTED_COMMAND_VERACK: [u8; 12] = [
        0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 00, 00, 00, 00, 00, 00, // - "verack" command
    ];

    #[test]
    fn test_message_command() {
        let cmd = MessageCommand::Verack;
        let cmd_array: [u8; 12] = (&cmd).into();
        assert_eq!(cmd_array, EXPECTED_COMMAND_VERACK);
    }

    /// From https://en.bitcoin.it/wiki/Protocol_documentation#Message_structure
    const EXPECTED_VERACK: [u8; 24] = [
        0xF9, 0xBE, 0xB4, 0xD9, // - Main network magic bytes
        0x76, 0x65, 0x72, 0x61, 0x63, 0x6B, 00, 00, 00, 00, 00, 00, // - "verack" command
        0x00, 0x00, 0x00, 0x00, // - Payload is 0 bytes long
        0x5D, 0xF6, 0xE0, 0xE2, // - Checksum (internal byte order)
    ];

    #[test]
    fn test_serialize_verack() {
        let msg_verack = Message::from((MessageMagic::Main, MessagePayload::Verack));
        let ser = MessageSerializer::new();
        let mut buffer = BytesMut::new();
        ser.serialize(&msg_verack, &mut buffer).unwrap();
        assert_eq!(buffer.as_bytes(), EXPECTED_VERACK);

        let der = MessageDeserializer::new();
        let (content, msg_raw_d) = der.deserialize(EXPECTED_VERACK.as_slice()).unwrap();
        assert!(content.is_empty());

        let der2 = MessagePayloadDeserializer::new();
        let msg_d = Message::try_from((msg_raw_d, der2)).unwrap();

        assert_eq!(msg_d, msg_verack);
    }
}
