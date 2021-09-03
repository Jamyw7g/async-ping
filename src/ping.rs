use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    sync::Arc,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use tokio::io::unix::AsyncFd;
use tokio::time::timeout;

use crate::error::{Error, Result};
use crate::packet::{icmpv4, icmpv6, IcmpPacket};

use crate::socket;

#[derive(Debug)]
pub struct AsyncSocket {
    inner: AsyncFd<socket::Socket>,
}

impl AsyncSocket {
    pub fn new(socket: socket::Socket) -> io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(socket)?,
        })
    }

    pub fn get_ref(&self) -> &socket::Socket {
        &self.inner.get_ref()
    }

    pub async fn send_to(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        loop {
            let mut gurad = self.inner.writable().await?;

            match gurad.try_io(|inner| inner.get_ref().sendto(buf, addr)) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recvmsg_v4(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        loop {
            let mut gurad = self.inner.readable().await?;

            match gurad.try_io(|inner| inner.get_ref().recvmsg_v4(buf)) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn recvmsg_v6(
        &self,
        buf: &mut [MaybeUninit<u8>],
    ) -> io::Result<(usize, Option<IpAddr>, Option<IpAddr>, Option<u32>)> {
        loop {
            let mut gurad = self.inner.readable().await?;

            match gurad.try_io(|inner| inner.get_ref().recvmsg_v6(buf)) {
                Ok(res) => return res,
                Err(_would_block) => continue,
            }
        }
    }
}

type Cache = DashMap<(u16, u16), Instant>;

#[allow(dead_code)]
#[derive(Debug)]
pub struct Pinger {
    dst: SocketAddr,
    idt: u16,
    size: usize,
    ttl: u8,
    timeout: Duration,
    sock: Arc<AsyncSocket>,
    cache: Arc<Cache>,
}

impl Pinger {
    pub fn new<S: ToSocketAddrs>(dst: S) -> Result<Self> {
        let dst = dst.to_socket_addrs()?.next().ok_or(Error::HostError)?;

        let sock = match dst {
            SocketAddr::V4(_) => socket::Socket::new_v4().map(AsyncSocket::new)??,
            SocketAddr::V6(_) => socket::Socket::new_v6().map(AsyncSocket::new)??,
        };

        let mut u16_buf = [0; 2];
        getrandom::getrandom(&mut u16_buf).unwrap();
        let idt = u16::from_ne_bytes(u16_buf);

        Ok(Self {
            dst,
            idt,
            size: 56,
            ttl: 64,
            timeout: Duration::from_secs(2),
            sock: Arc::new(sock),
            cache: Arc::new(DashMap::new()),
        })
    }

    async fn recv_reply(&self, seq: u16) -> Result<(IcmpPacket, Duration)> {
        let mut buffer = [MaybeUninit::<u8>::uninit(); 2048];
        loop {
            let packet: Result<_> = match self.dst {
                SocketAddr::V4(_) => {
                    let size = self.sock.recvmsg_v4(&mut buffer).await?;
                    let packet: &[u8] = unsafe { mem::transmute(&buffer[..size]) };
                    let packet = icmpv4::Icmpv4Packet::decode(packet).map(IcmpPacket::V4)?;
                    if !packet.check(self.dst.ip(), seq, self.idt) {
                        continue;
                    }
                    Ok(packet)
                }
                SocketAddr::V6(_) => {
                    let (size, src, dst, hlim) = self.sock.recvmsg_v6(&mut buffer).await?;
                    let packet: &[u8] = unsafe { mem::transmute(&buffer[..size]) };
                    let src = src.ok_or(Error::Ipv6Addr)?;
                    let dst = dst.ok_or(Error::Ipv6Addr)?;
                    let hlim = hlim.map(|v| v as u8);
                    let packet = match icmpv6::Icmpv6Packet::decode(packet, src, dst, hlim)
                        .map(IcmpPacket::V6)
                    {
                        Ok(packet) => packet,
                        Err(e) => {
                            log::error!("Receive packet error: {}", e);
                            continue;
                        }
                    };
                    if !packet.check(self.dst.ip(), seq, self.idt) {
                        continue;
                    }
                    Ok(packet)
                }
            };
            match packet {
                Ok(packet) => {
                    if let Some((_, val)) = self.cache.remove(&(self.idt, seq)) {
                        return Ok((packet, val.elapsed()));
                    }
                }
                Err(e) => {
                    log::error!("Receive packet error: {}", e);
                    continue;
                }
            }
        }
    }

    pub async fn ping(&self, seq: u16, data: Option<&[u8]>) -> Result<(IcmpPacket, Duration)> {
        if let Some(data) = data {
            assert!(data.len() <= self.size);
        }
        let packet = match self.dst {
            SocketAddr::V4(_) => icmpv4::make_echo_packet(self.idt, seq, self.size, data),
            SocketAddr::V6(_) => icmpv6::make_echo_packet(self.idt, seq, self.size, data),
        };
        let packet = packet.unwrap();

        let addr = self.dst;
        let ident = self.idt;
        let cache = Arc::clone(&self.cache);
        let sender = Arc::clone(&self.sock);
        tokio::spawn(async move {
            if let Err(e) = sender.send_to(&packet, &addr).await {
                log::error!("socket send packet error: {}", e);
            }
            cache.insert((ident, seq), Instant::now());
        });

        match timeout(self.timeout, self.recv_reply(seq)).await {
            Ok(res) => res.map_err(|e| {
                self.cache.remove(&(ident, seq));
                e
            }),
            Err(_) => {
                self.cache.remove(&(ident, seq));
                Err(Error::Timeout { seq })
            }
        }
    }
}
