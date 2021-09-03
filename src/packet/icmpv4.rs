use std::convert::TryInto;
use std::net::Ipv4Addr;

use pnet_packet::icmp::IcmpTypes::EchoRequest;
use pnet_packet::icmp::{self, IcmpCode, IcmpType};
use pnet_packet::{ipv4, Packet};

use crate::error::{Error, MalformedPacketError, Result};

pub fn make_echo_packet(
    idt: u16,
    seq: u16,
    size: usize,
    payload: Option<&[u8]>,
) -> Result<Vec<u8>> {
    let mut buf = vec![0; 8 + size];
    let mut packet = icmp::echo_request::MutableEchoRequestPacket::new(&mut buf)
        .ok_or(Error::IncorrectBufferSize)?;

    packet.set_icmp_type(EchoRequest);
    packet.set_identifier(idt);
    packet.set_sequence_number(seq);
    if let Some(payload) = payload {
        packet.set_payload(payload);
    }

    let icmp_packet = icmp::IcmpPacket::new(packet.packet()).ok_or(Error::IncorrectBufferSize)?;
    let checksum = icmp::checksum(&icmp_packet);
    packet.set_checksum(checksum);

    Ok(buf)
}

#[derive(Debug)]
pub struct Icmpv4Packet {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub ttl: u8,
    pub icmp_type: IcmpType,
    pub icmp_code: IcmpCode,
    pub size: usize,
    pub real_dest: Ipv4Addr,
    pub identifier: u16,
    pub sequence: u16,
}

impl Icmpv4Packet {
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let ipv4_packet = ipv4::Ipv4Packet::new(buf)
            .ok_or_else(|| Error::from(MalformedPacketError::NotIpv4Packet))?;
        let payload = ipv4_packet.payload();
        let icmp_packet = icmp::IcmpPacket::new(payload)
            .ok_or_else(|| Error::from(MalformedPacketError::NotIcmpv4Packet))?;

        match icmp_packet.get_icmp_type() {
            icmp::IcmpTypes::EchoReply => {
                let icmp_packet = icmp::echo_reply::EchoReplyPacket::new(payload)
                    .ok_or_else(|| Error::from(MalformedPacketError::NotIcmpv4Packet))?;
                Ok(Self {
                    source: ipv4_packet.get_source(),
                    destination: ipv4_packet.get_destination(),
                    ttl: ipv4_packet.get_ttl(),
                    icmp_type: icmp_packet.get_icmp_type(),
                    icmp_code: icmp_packet.get_icmp_code(),
                    size: icmp_packet.packet().len(),
                    real_dest: ipv4_packet.get_source(),
                    identifier: icmp_packet.get_identifier(),
                    sequence: icmp_packet.get_sequence_number(),
                })
            }
            icmp::IcmpTypes::EchoRequest => Err(Error::EchoRequestPacket),
            _ => {
                let icmp_payload = icmp_packet.payload();
                let real_ip_packet = ipv4::Ipv4Packet::new(&icmp_payload[4..])
                    .ok_or_else(|| Error::from(MalformedPacketError::NotIpv4Packet))?;
                let identifier = u16::from_be_bytes(icmp_payload[28..30].try_into().unwrap());
                let sequence = u16::from_be_bytes(icmp_payload[30..32].try_into().unwrap());
                Ok(Self {
                    source: ipv4_packet.get_source(),
                    destination: ipv4_packet.get_destination(),
                    ttl: ipv4_packet.get_ttl(),
                    icmp_type: icmp_packet.get_icmp_type(),
                    icmp_code: icmp_packet.get_icmp_code(),
                    size: icmp_packet.packet().len(),
                    real_dest: real_ip_packet.get_source(),
                    identifier,
                    sequence,
                })
            }
        }
    }
}
