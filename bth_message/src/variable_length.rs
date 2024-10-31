use std::error::Error;

use bytes::BufMut;
use nom::number::complete::{le_u16, le_u32, le_u64, u8};

use crate::serialization::{Deserializer, NomError, Serializer};

pub(crate) struct VarIntSerializer {}

impl Serializer<usize> for VarIntSerializer {
    fn serialize<B: BufMut>(&self, value: &usize, mut buffer: B) -> Result<(), Box<dyn Error>> {
        // From <https://en.bitcoin.it/wiki/Protocol_documentation#Variable_length_string>
        match value {
            v if *v < 0xFD => buffer.put_u8(*v as u8),
            v if *v <= 0xFFFF => {
                buffer.put_u8(0xFD);
                buffer.put_u16_le(*v as u16);
            }
            v if *v <= 0xFFFFFFFF => {
                buffer.put_u8(0xFE);
                buffer.put_u32_le(*v as u32);
            }
            _ => {
                buffer.put_u8(0xFF);
                buffer.put_u64_le(*value as u64);
            }
        };

        Ok(())
    }
}

#[derive(Clone)]
pub(crate) struct VarIntDeserializer {}

impl Deserializer<usize> for VarIntDeserializer {
    fn deserialize<'a>(&self, buffer: &'a [u8]) -> Result<(&'a [u8], usize), Box<dyn Error + 'a>> {
        let (content, value) = u8::<_, NomError>(buffer)?;

        match value {
            v if v < 0xFD => Ok((content, usize::from(value))),
            0xFD => {
                let (content, value_) = le_u16::<_, NomError>(content)?;
                Ok((content, usize::from(value_)))
            }
            0xFE => {
                let (content, value_) = le_u32::<_, NomError>(content)?;
                Ok((content, usize::try_from(value_)?))
            }
            0xFF => {
                let (content, value_) = le_u64::<_, NomError>(content)?;
                Ok((content, usize::try_from(value_)?))
            }
            _ => Err("Invalid var int encoding".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;

    #[test]
    fn test_encode() {
        let ser = VarIntSerializer {};
        let mut buffer = BytesMut::new();

        ser.serialize(&0, &mut buffer).unwrap();
        assert_eq!(buffer.to_vec(), vec![0x0]);

        // TODO
        // let res = usize_encode(15);
        // assert_eq!(res, vec![0x0F]);
        // let res = usize_encode(252);
        // assert_eq!(res, vec![0xFC]);

        // let res = usize_encode(65535);
        // assert_eq!(res, vec![0xFD, 0xFF, 0xFF]);

        // let res = usize_encode(4294967295);
        // assert_eq!(res, vec![0xFE, 0xFF, 0xFF, 0xFF, 0xFF]);

        // let res = usize_encode(4294967295 + 1);
        // assert_eq!(res, vec![0xFF, 0, 0, 0, 0, 1, 0, 0, 0]);
    }
}
