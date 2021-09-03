use std::net::IpAddr;

pub mod icmpv4;
pub mod icmpv6;

#[derive(Debug)]
pub enum IcmpPacket {
    V4(icmpv4::Icmpv4Packet),
    V6(icmpv6::Icmpv6Packet),
}

impl IcmpPacket {
    pub fn check(&self, destination: IpAddr, sequence: u16, identifier: u16) -> bool {
        match self {
            IcmpPacket::V4(packet) => {
                destination == packet.real_dest
                    && sequence == packet.sequence
                    && identifier == packet.identifier
            }
            IcmpPacket::V6(packet) => {
                destination == packet.real_dest
                    && sequence == packet.sequence
                    && identifier == packet.identifier
            }
        }
    }
}
