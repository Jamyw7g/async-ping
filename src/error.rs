pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("buffer size was too small")]
    IncorrectBufferSize,
    #[error("malformed packet: {0}")]
    MalformedPacket(#[from] MalformedPacketError),
    #[error("io error")]
    IOError(#[from] std::io::Error),
    #[error("Request timeout for icmp_seq {seq}")]
    Timeout { seq: u16 },
    #[error("Echo Request packet.")]
    EchoRequestPacket,
    #[error("Network error.")]
    NetworkError,
    #[error("Unknown host")]
    HostError,
    #[error("Ipv4 error.")]
    Ipv4Addr,
    #[error("Ipv6 error.")]
    Ipv6Addr,
    #[error("Other packet")]
    OtherPacket,
}

#[derive(thiserror::Error, Debug)]
pub enum MalformedPacketError {
    #[error("expected an Ipv4Packet")]
    NotIpv4Packet,
    #[error("expected an Ipv6Packet")]
    NotIpv6Packet,
    #[error("expected an Icmpv4Packet payload")]
    NotIcmpv4Packet,
    #[error("expected an Icmpv6Packet")]
    NotIcmpv6Packet,
    #[error("payload too short, got {got}, want {want}")]
    PayloadTooShort { got: usize, want: usize },
}
