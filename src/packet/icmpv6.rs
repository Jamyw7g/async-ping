use std::convert::TryInto;
use std::net::{IpAddr, Ipv6Addr};

use pnet_packet::icmpv6::{self, Icmpv6Code, Icmpv6Type, Icmpv6Types};
use pnet_packet::Packet;

use crate::error::MalformedPacketError;
use crate::{error::Error, Result};

pub fn make_echo_packet(
    idt: u16,
    seq: u16,
    size: usize,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut buf = vec![0; 8 + size];
    let mut packet =
        icmpv6::MutableIcmpv6Packet::new(&mut buf).ok_or(Error::IncorrectBufferSize)?;

    packet.set_icmpv6_type(Icmpv6Types::EchoRequest);
    let idt_bytes = idt.to_be_bytes();
    let seq_bytes = seq.to_be_bytes();
    let mut payload_buf = Vec::with_capacity(4 + size);
    payload_buf.extend_from_slice(&idt_bytes);
    payload_buf.extend_from_slice(&seq_bytes);
    if let Some(payload) = payload {
        payload_buf.extend_from_slice(payload);
    }
    packet.set_payload(&payload_buf);

    // checksum
    // The kernel will calculate checksum of icmpv6 in default.
    Ok(buf)
}

#[derive(Debug)]
pub struct Icmpv6Packet {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub hop_limit: Option<u8>,
    pub icmp_type: Icmpv6Type,
    pub icmp_code: Icmpv6Code,
    pub size: usize,
    pub real_dest: Ipv6Addr,
    pub identifier: u16,
    pub sequence: u16,
}

impl Icmpv6Packet {
    pub fn decode(buf: &[u8], src: IpAddr, dst: IpAddr, hlim: Option<u8>) -> Result<Self> {
        let icmpv6_packet = icmpv6::Icmpv6Packet::new(buf)
            .ok_or_else(|| Error::from(MalformedPacketError::NotIcmpv6Packet))?;

        let source = if let IpAddr::V6(ip) = src {
            ip
        } else {
            return Err(Error::Ipv6Addr);
        };
        let destination = if let IpAddr::V6(ip) = dst {
            ip
        } else {
            return Err(Error::Ipv6Addr);
        };

        match icmpv6_packet.get_icmpv6_type() {
            icmpv6::Icmpv6Types::EchoReply => {
                let icmpv6_payload = icmpv6_packet.payload();
                let identifier = u16::from_be_bytes(icmpv6_payload[0..2].try_into().unwrap());
                let sequence = u16::from_be_bytes(icmpv6_payload[2..4].try_into().unwrap());
                Ok(Self {
                    source,
                    destination,
                    hop_limit: hlim,
                    icmp_type: icmpv6_packet.get_icmpv6_type(),
                    icmp_code: icmpv6_packet.get_icmpv6_code(),
                    size: icmpv6_packet.packet().len(),
                    real_dest: source,
                    identifier,
                    sequence,
                })
            }
            _ => Err(Error::OtherPacket),
        }
    }
}
