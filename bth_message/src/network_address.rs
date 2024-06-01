use std::error::Error;
use std::net::{IpAddr, Ipv6Addr};

use bytes::BufMut;
use nom::bytes::complete::take;
use nom::number::complete::{be_u16, le_i64};

use crate::serialization::{Deserializer, Serializer};
use crate::services::Services;

const IPV4_MAPPED_IPV6_PADDING: [u8; 12] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF,
];

/// From <https://en.bitcoin.it/wiki/Protocol_documentation#Network_address>
#[derive(Debug, Clone, PartialEq)]
pub struct NetAddress {
    /// the Time (version >= 31402). Not present in version message.
    // time: u32,
    /// same service(s) listed in version
    pub(crate) services: Services,
    /// IPv6 address. Network byte order. The original client only supported IPv4
    /// and only read the last 4 bytes to get the IPv4 address.
    /// However, the IPv4 address is written into the message as a 16 byte IPv4-mapped IPv6 address
    /// (12 bytes 00 00 00 00 00 00 00 00 00 00 FF FF, followed by the 4 bytes of the IPv4 address).
    // ip: [u8; 16],
    pub(crate) ip: IpAddr,
    /// port number, network byte order
    pub(crate) port: u16,
}

pub struct NetAddressSerializer {}

impl Serializer<NetAddress> for NetAddressSerializer {
    fn serialize<B: BufMut>(
        &self,
        value: &NetAddress,
        mut buffer: B,
    ) -> Result<(), Box<dyn Error>> {
        buffer.put_i64_le(value.services.bits());
        match value.ip {
            IpAddr::V4(ipv4) => {
                buffer.put(IPV4_MAPPED_IPV6_PADDING.as_slice());
                buffer.put(ipv4.octets().as_slice());
            }
            IpAddr::V6(ipv6) => buffer.put(ipv6.octets().as_slice()),
        }
        buffer.put_u16(value.port);
        Ok(())
    }

    // fn size_hint(_value: &NetAddress) -> (usize, Option<usize>) {
    //     let size = 8 + 16 + 2; // i64 services + ip + u16 port
    //     (size, Some(size))
    // }
}

#[derive(Clone)]
pub struct NetAddressDeserializer {}

impl Deserializer<NetAddress> for NetAddressDeserializer {
    fn deserialize<'a>(
        &self,
        buffer: &'a [u8],
    ) -> Result<(&'a [u8], NetAddress), Box<dyn Error + 'a>> {
        let (content, services_) = le_i64::<&[u8], nom::error::Error<&[u8]>>(buffer)?;
        let services = Services::from_bits(services_).ok_or("Unknown services")?;
        let (content, ip_) = take::<usize, &[u8], nom::error::Error<&[u8]>>(16usize)(content)?;
        let ipv6_: &[u8; 16] = ip_.try_into().unwrap();
        let ipv6 = Ipv6Addr::from(*ipv6_);
        let ip = IpAddr::from(ipv6);
        let (content, port) = be_u16::<&[u8], nom::error::Error<&[u8]>>(content)?;
        Ok((content, NetAddress { services, ip, port }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::BytesMut;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    /// From https://en.bitcoin.it/wiki/Protocol_documentation#Network_address
    const EXPECTED: [u8; 26] = [
        01, 00, 00, 00, 00, 00, 00,
        00, // - 1 (NODE_NETWORK: see services listed under version command)
        00, 00, 00, 00, 00, 00, 00, 00, 00, 00, 0xFF, 0xFF, 0x0A, 00, 00,
        01, // - IPv6: ::ffff:a00:1 or IPv4: 10.0.0.1
        0x20, 0x8D, // - Port 8333
    ];

    #[test]
    fn test_serialize_ipv6() {
        let net_addr_1 = NetAddress {
            services: Services::NODE_NETWORK,
            ip: Ipv6Addr::from_str("::ffff:a00:1").unwrap().into(),
            port: 8333,
        };

        let ser = NetAddressSerializer {};
        let mut buffer = BytesMut::new();
        ser.serialize(&net_addr_1, &mut buffer).unwrap();
        assert_eq!(buffer.as_ref(), EXPECTED);

        let der = NetAddressDeserializer {};
        let (content, net_addr_d) = der.deserialize(EXPECTED.as_slice()).unwrap();
        assert!(content.is_empty());
        assert_eq!(net_addr_d, net_addr_1);
    }

    #[test]
    fn test_serialize_ipv4() {
        let net_addr_1 = NetAddress {
            services: Services::NODE_NETWORK,
            ip: Ipv4Addr::from_str("10.0.0.1").unwrap().into(),
            port: 8333,
        };

        let ser = NetAddressSerializer {};
        let mut buffer = BytesMut::new();
        ser.serialize(&net_addr_1, &mut buffer).unwrap();
        assert_eq!(buffer.as_ref(), EXPECTED);
    }
}
