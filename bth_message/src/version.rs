use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};

use bytes::BufMut;
use nom::bytes::complete::take;
use nom::number::complete::{le_i32, le_i64, le_u64, u8};

use crate::network_address::{NetAddress, NetAddressDeserializer, NetAddressSerializer};
use crate::serialization::{Deserializer, NomError, Serializer};
use crate::services::Services;
use crate::variable_length::{VarIntDeserializer, VarIntSerializer};

#[derive(Debug, Clone, PartialEq)]
pub struct Version {
    /// Identifies protocol version being used by the node
    version: i32,
    /// bitfield of features to be enabled for this connection
    services: Services,
    /// standard UNIX timestamp in seconds
    timestamp: i64,
    /// The network address of the node receiving this message
    addr_recv: NetAddress,
    /// Fields below require version ≥ 106
    /// Field can be ignored. This used to be the network address of the node emitting this message,
    /// but most P2P implementations send 26 dummy bytes.
    /// The "services" field of the address would also be redundant with the second field of the
    /// version message.
    addr_from: NetAddress,
    /// Node random nonce, randomly generated every time a version packet is sent.
    /// This nonce is used to detect connections to self.
    nonce: u64,
    /// User Agent (0x00 if string is 0 bytes long)
    user_agent: String,
    /// The last block received by the emitting node
    start_height: i32,
    /// Fields below require version ≥ 70001
    /// Whether the remote peer should announce relayed transactions or not, see BIP 0037
    relay: bool,
}

impl Version {
    pub fn new(ipaddr_recv: IpAddr, port_recv: u16, nonce: u64, now: i64) -> Self {
        // version & user_agent from:
        // https://github.com/bitcoin/bitcoin/blob/master/src/node/protocol_version.h
        Self {
            version: 70015,
            services: Services::NODE_NETWORK,
            timestamp: now,
            addr_recv: NetAddress {
                services: Services::NODE_NETWORK,
                ip: ipaddr_recv,
                port: port_recv,
            },
            addr_from: NetAddress {
                services: Services::NODE_NETWORK,
                ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port: 0,
            },
            nonce,
            user_agent: "/Satoshi:27.0.0/".to_string(),
            start_height: 845890,
            relay: true,
        }
    }
}

/*
impl Version {
    pub(crate) fn ser(&self, buffer: &mut Vec<u8>) {
        buffer.extend(self.version.to_le_bytes());
        buffer.extend(self.services.bits().to_le_bytes());
        buffer.extend(self.timestamp.to_le_bytes());
        self.addr_recv.ser(buffer);
        self.addr_from.ser(buffer);
        buffer.extend(self.nonce.to_le_bytes());
        buffer.extend(usize_encode(self.user_agent.len()));
        buffer.extend(self.user_agent.as_bytes());
        buffer.extend(self.start_height.to_le_bytes());
        buffer.push(self.relay as u8);
    }
}
*/

pub(crate) struct VersionSerializer {
    addr_serializer: NetAddressSerializer,
    var_int_serializer: VarIntSerializer,
}

impl VersionSerializer {
    pub fn new() -> Self {
        Self {
            addr_serializer: NetAddressSerializer {},
            var_int_serializer: VarIntSerializer {},
        }
    }
}

impl Serializer<Version> for VersionSerializer {
    fn serialize<B: BufMut>(&self, value: &Version, mut buffer: B) -> Result<(), Box<dyn Error>> {
        buffer.put_i32_le(value.version);
        // let rem: [u8; 82] = [0; 82];
        // buffer.put(rem.as_slice());
        buffer.put_i64_le(value.services.bits());
        buffer.put_i64_le(value.timestamp);
        self.addr_serializer
            .serialize(&value.addr_recv, &mut buffer)?;
        self.addr_serializer
            .serialize(&value.addr_from, &mut buffer)?;
        buffer.put_u64_le(value.nonce);
        self.var_int_serializer
            .serialize(&value.user_agent.len(), &mut buffer)?;
        buffer.put(value.user_agent.as_bytes());
        buffer.put_i32_le(value.start_height);
        buffer.put_u8(u8::from(value.relay));
        Ok(())
    }

    // fn size_hint(value: &Version) -> (usize, Option<usize>) {

    //     let size = 4 + 8 + 8 + 1 + 8 + 4 + 8;
    //     if let (min_size, Some(max_size)) = NetAddressSerializer::size_hint(value.) {
    //
    //
    //
    //     } else {
    //         (size, None)
    //     }
    // }
}

#[derive(Clone)]
pub(crate) struct VersionDeserializer {
    net_address_deserializer: NetAddressDeserializer,
    var_int_deserializer: VarIntDeserializer,
}

impl VersionDeserializer {
    pub fn new() -> Self {
        Self {
            net_address_deserializer: NetAddressDeserializer {},
            var_int_deserializer: VarIntDeserializer {},
        }
    }
}

impl Deserializer<Version> for VersionDeserializer {
    fn deserialize<'a>(
        &self,
        buffer: &'a [u8],
    ) -> Result<(&'a [u8], Version), Box<dyn Error + 'a>> {
        let (content, version) = le_i32::<_, NomError>(buffer)?;
        let (content, services_) = le_i64::<&[u8], NomError>(content)?;
        let services = Services::from_bits(services_).ok_or("Unknown services")?;
        let (content, ts) = le_i64::<&[u8], NomError>(content)?;

        let (content, addr_recv) = self.net_address_deserializer.deserialize(content)?;
        let (content, addr_from) = self.net_address_deserializer.deserialize(content)?;

        let (content, nonce) = le_u64::<&[u8], NomError>(content)?;

        let (content, user_agent_len) = self.var_int_deserializer.deserialize(content)?;
        let (content, user_agent_) = take::<_, &[u8], NomError>(user_agent_len)(content)?;

        let (content, start_height) = le_i32::<_, NomError>(content)?;
        let (content, relay_) = u8::<_, NomError>(content)?;

        let relay = match relay_ {
            0 => false,
            1 => true,
            _ => return Err("Unable to convert relay value to bool".into()),
        };

        let version = Version {
            version,
            services,
            timestamp: ts,
            addr_recv,
            addr_from,
            nonce,
            user_agent: String::from_utf8(user_agent_.to_vec())?,
            start_height,
            relay,
        };

        Ok((content, version))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use bytes::BytesMut;
    use nom::AsBytes;

    // From <https://en.bitcoin.it/wiki/Protocol_documentation#Network_address>
    // Modified: recipient address info & Sender address info
    // Added: relay
    const EXPECTED: [u8; 101] = [
        0x62, 0xEA, 0x00, 0x00, // - 60002 (protocol version 60002)
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // - 1 (NODE_NETWORK services)
        0x11, 0xB2, 0xD0, 0x50, 0x00, 0x00, 0x00, 0x00, // - Tue Dec 18 10:12:33 PST 2012
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 00, 00, 00, 00, 00,
        00, 0xFF, 0xFF, 0x0A, 00, 00, 01, 00,
        00, // - Recipient address info - see Network Address
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 00, 00, 00, 00, 00,
        00, 0xFF, 0xFF, 0x0A, 00, 00, 02, 00,
        00, // - Sender address info - see Network Address
        0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65, // - Node ID
        0x0F, 0x2F, 0x53, 0x61, 0x74, 0x6F, 0x73, 0x68, 0x69, 0x3A, 0x30, 0x2E, 0x37, 0x2E, 0x32,
        0x2F, // - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
        0xC0, 0x3E, 0x03, 0x00, // - Last block sending node has is block #212672
        0x00, // - relay
    ];

    #[test]
    fn test_serialize_version() {
        let net_addr_r = NetAddress {
            services: Services::NODE_NETWORK,
            ip: Ipv6Addr::from_str("::ffff:a00:1").unwrap().into(),
            port: 0,
        };

        let net_addr_f = NetAddress {
            services: Services::NODE_NETWORK,
            ip: Ipv6Addr::from_str("::ffff:a00:2").unwrap().into(),
            port: 0,
        };

        let version = Version {
            version: 60002,
            services: Services::NODE_NETWORK,
            timestamp: i64::from_le_bytes([0x11, 0xB2, 0xD0, 0x50, 0x00, 0x00, 0x00, 0x00]),
            addr_recv: net_addr_r,
            addr_from: net_addr_f,
            nonce: u64::from_le_bytes([0x3B, 0x2E, 0xB3, 0x5D, 0x8C, 0xE6, 0x17, 0x65]),
            user_agent: "/Satoshi:0.7.2/".to_string(),
            start_height: 212672,
            relay: false,
        };

        let ser = VersionSerializer {
            addr_serializer: NetAddressSerializer {},
            var_int_serializer: VarIntSerializer {},
        };
        let mut buffer = BytesMut::new();
        ser.serialize(&version, &mut buffer).unwrap();
        assert_eq!(buffer.as_bytes(), EXPECTED);

        let der = VersionDeserializer {
            net_address_deserializer: NetAddressDeserializer {},
            var_int_deserializer: VarIntDeserializer {},
        };
        let (content, version_d) = der.deserialize(EXPECTED.as_slice()).unwrap();
        assert!(content.is_empty());
        assert_eq!(version_d, version);
    }
}
