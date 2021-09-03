use crate::sys;
use std::os::unix::io::{AsRawFd, RawFd};
use std::{
    io,
    mem::{self, MaybeUninit},
    net::{IpAddr, Ipv6Addr, SocketAddr},
    ptr::null_mut,
};

use libc::c_int;

pub(crate) type Inner = std::net::TcpStream;

#[derive(Debug)]
pub struct Socket {
    inner: Inner
}

impl AsRawFd for Socket {
    fn as_raw_fd(&self) -> RawFd {
        self.as_raw()
    }
}

impl Socket {
    pub(crate) fn from_raw(raw: sys::Socket) -> Self {
        Self {
            inner: unsafe { sys::socket_from_raw(raw) },
        }
    }
    pub(crate) fn as_raw(&self) -> sys::Socket {
        sys::socket_as_raw(&self.inner)
    }

    pub(crate) fn into_raw(self) -> sys::Socket {
        sys::socket_into_raw(self.inner)
    }
}

impl Socket {
    pub fn new_v4() -> io::Result<Self> {
        sys::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_ICMP)
            .map(Self::from_raw)
            .and_then(set_common_flags)
            .and_then(init_v4)
    }

    pub fn new_v6() -> io::Result<Self> {
        sys::socket(libc::AF_INET6, libc::SOCK_RAW, libc::IPPROTO_ICMPV6)
            .map(Self::from_raw)
            .and_then(set_common_flags)
            .and_then(init_v6)
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        sys::set_nonblocking(self.as_raw(), nonblocking)
    }

    pub fn set_ttl(&self, ttl: u32) -> io::Result<()> {
        sys::setsockopt(self.as_raw(), libc::IPPROTO_IP, libc::IP_TTL, ttl as c_int)
    }

    pub fn sendto(&self, buf: &[u8], addr: &SocketAddr) -> io::Result<usize> {
        sys::sendto(self.as_raw(), buf, addr, 0)
    }

    pub fn recvmsg_v4(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<usize> {
        let mut bufs = [sys::MaybeUninitSlice::new(buf)];
        let (n, _) = sys::recvmsg(self.as_raw(), null_mut(), &mut bufs, &mut [], 0)?;
        Ok(n)
    }

    pub fn recvmsg_v6(
        &self,
        buf: &mut [MaybeUninit<u8>],
    ) -> io::Result<(usize, Option<IpAddr>, Option<IpAddr>, Option<u32>)> {
        let mut bufs = [sys::MaybeUninitSlice::new(buf)];
        let mut control = [MaybeUninit::uninit(); 1500];
        let mut addr = unsafe { mem::zeroed() };
        let (n, msg) = sys::recvmsg(self.as_raw(), &mut addr, &mut bufs, &mut control, 0)?;
        let addr_storage = msg.msg_name as *const libc::sockaddr_storage;
        let src = unsafe {
            if (*addr_storage).ss_family == libc::AF_INET as libc::sa_family_t {
                let addr = addr_storage as *const libc::sockaddr_in;
                Some(IpAddr::V4(sys::from_in_addr((*addr).sin_addr)))
            } else if (*addr_storage).ss_family == libc::AF_INET6 as libc::sa_family_t {
                let addr = addr_storage as *const libc::sockaddr_in6;
                Some(IpAddr::V6(sys::from_in6_addr((*addr).sin6_addr)))
            } else {
                None
            }
        };
        let dst = unsafe {
            msg.find(libc::IPPROTO_IPV6, sys::IPV6_RECVPKTINFO)
                .map(|val| {
                    IpAddr::V6(Ipv6Addr::from(
                        (*(val as *const libc::in6_pktinfo)).ipi6_addr.s6_addr,
                    ))
                })
        };
        let hlim = unsafe {
            msg.find(libc::IPPROTO_IPV6, sys::IPV6_HOPLIMIT)
                .map(|val| *(val as *const u32))
        };
        Ok((n, src, dst, hlim))
    }
}

fn set_common_flags(socket: Socket) -> io::Result<Socket> {
    // On platforms that don't have `SOCK_CLOEXEC` use `FD_CLOEXEC`.
    #[cfg(all(
        unix,
        not(any(
            target_os = "android",
            target_os = "dragonfly",
            target_os = "freebsd",
            target_os = "fuchsia",
            target_os = "illumos",
            target_os = "linux",
            target_os = "netbsd",
            target_os = "openbsd",
        ))
    ))]
    socket._set_cloexec(true)?;

    // On Apple platforms set `NOSIGPIPE`.
    #[cfg(target_vendor = "apple")]
    socket._set_nosigpipe(true)?;

    Ok(socket)
}

fn init_v4(sock: Socket) -> io::Result<Socket> {
    Ok(sock)
}

fn init_v6(sock: Socket) -> io::Result<Socket> {
    sys::setsockopt(sock.as_raw(), libc::IPPROTO_IPV6, sys::IPV6_HOPLIMIT, 1)?;
    sys::setsockopt(sock.as_raw(), libc::IPPROTO_IPV6, sys::IPV6_RECVPKTINFO, 1)?;
    Ok(sock)
}
