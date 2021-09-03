use std::marker::PhantomData;
use std::mem::{self, MaybeUninit};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::ops::Deref;
use std::os::unix::io::{AsRawFd, FromRawFd, IntoRawFd};
use std::ptr;
use std::slice;
use std::{io, mem::size_of};

use libc::sockaddr_storage;
use libc::{c_int, c_void};

#[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
pub(crate) use libc::{IPV6_HOPLIMIT, IPV6_RECVPKTINFO};
#[cfg(target_vendor = "apple")]
pub(crate) const IPV6_RECVPKTINFO: libc::c_int = 19;
#[cfg(target_vendor = "apple")]
pub(crate) const IPV6_HOPLIMIT: libc::c_int = 20;

pub(crate) type Socket = c_int;

macro_rules! syscall {
    ($fn:ident ($($args:expr),* $(,)*)) => {
        {
            let res = unsafe { libc::$fn($($args),*) };
            if res == -1 {
                Err(std::io::Error::last_os_error())
            } else {
                Ok(res)
            }
        }
    };
}

#[repr(transparent)]
pub(crate) struct MaybeUninitSlice<'a> {
    vec: libc::iovec,
    _lifetime: PhantomData<&'a mut MaybeUninit<u8>>,
}

impl<'a> MaybeUninitSlice<'a> {
    pub(crate) fn new(buf: &'a mut [MaybeUninit<u8>]) -> Self {
        Self {
            vec: libc::iovec {
                iov_base: buf.as_mut_ptr().cast(),
                iov_len: buf.len(),
            },
            _lifetime: PhantomData,
        }
    }

    pub(crate) fn as_slice(&self) -> &[MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts(self.vec.iov_base.cast(), self.vec.iov_len) }
    }

    pub(crate) fn as_mut_slice(&mut self) -> &mut [MaybeUninit<u8>] {
        unsafe { slice::from_raw_parts_mut(self.vec.iov_base.cast(), self.vec.iov_len) }
    }
}

#[repr(transparent)]
pub(crate) struct MsgHdr<'a> {
    msg: libc::msghdr,
    _lifetime: PhantomData<&'a mut [MaybeUninit<u8>]>,
}

impl<'a> MsgHdr<'a> {
    pub(crate) fn new(msg: libc::msghdr) -> Self {
        Self {
            msg,
            _lifetime: PhantomData,
        }
    }

    pub(crate) unsafe fn find(&self, level: c_int, ty: c_int) -> Option<*mut u8> {
        let mut cmsg = libc::CMSG_FIRSTHDR(&self.msg);
        while !cmsg.is_null() {
            if (*cmsg).cmsg_level == level && (*cmsg).cmsg_type == ty {
                return Some(libc::CMSG_DATA(cmsg));
            }
            cmsg = libc::CMSG_NXTHDR(&self.msg, cmsg);
        }
        None
    }
}

impl<'a> Deref for MsgHdr<'a> {
    type Target = libc::msghdr;

    fn deref(&self) -> &Self::Target {
        &self.msg
    }
}

pub(crate) unsafe fn socket_from_raw(sock: Socket) -> crate::socket::Inner {
    crate::socket::Inner::from_raw_fd(sock)
}

pub(crate) fn socket_as_raw(sock: &crate::socket::Inner) -> Socket {
    sock.as_raw_fd()
}

pub(crate) fn socket_into_raw(sock: crate::socket::Inner) -> Socket {
    sock.into_raw_fd()
}

pub(crate) fn socket(family: c_int, ty: c_int, protocol: c_int) -> io::Result<Socket> {
    syscall!(socket(family, ty, protocol))
}

pub(crate) fn set_nonblocking(fd: Socket, nonblocking: bool) -> io::Result<()> {
    if nonblocking {
        fcntl_add(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    } else {
        fcntl_remove(fd, libc::F_GETFL, libc::F_SETFL, libc::O_NONBLOCK)
    }
}

fn fcntl_add(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let pre = syscall!(fcntl(fd, get_cmd))?;
    let new = pre | flag;
    if new != pre {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        Ok(())
    }
}

fn fcntl_remove(fd: Socket, get_cmd: c_int, set_cmd: c_int, flag: c_int) -> io::Result<()> {
    let pre = syscall!(fcntl(fd, get_cmd))?;
    let new = pre & !flag;
    if new != pre {
        syscall!(fcntl(fd, set_cmd, new)).map(|_| ())
    } else {
        Ok(())
    }
}

pub(crate) fn setsockopt<T>(sock: Socket, opt: c_int, val: c_int, payload: T) -> io::Result<()> {
    let payload = &payload as *const T as *const c_void;
    syscall!(setsockopt(
        sock,
        opt,
        val,
        payload,
        size_of::<T>() as libc::socklen_t
    ))
    .map(|_| ())
}

pub(crate) fn recvmsg<'h>(
    sock: Socket,
    msg_name: *mut sockaddr_storage,
    bufs: &'h mut [MaybeUninitSlice<'_>],
    control_buf: &'h mut [MaybeUninit<u8>],
    flags: c_int,
) -> io::Result<(usize, MsgHdr<'h>)> {
    let msg_name_len = if msg_name.is_null() {
        0
    } else {
        size_of::<sockaddr_storage>() as libc::socklen_t
    };

    let mut msg: libc::msghdr = unsafe { mem::zeroed() };
    msg.msg_name = msg_name.cast();
    msg.msg_namelen = msg_name_len;
    msg.msg_iov = bufs.as_mut_ptr().cast();
    msg.msg_iovlen = bufs.len() as _;
    msg.msg_control = control_buf.as_mut_ptr().cast();
    msg.msg_controllen = control_buf.len() as _;
    syscall!(recvmsg(sock, &mut msg, flags)).map(|n| (n as usize, MsgHdr::new(msg)))
}

pub(crate) fn sendto(
    sock: Socket,
    buf: &[u8],
    addr: &SocketAddr,
    flags: c_int,
) -> io::Result<usize> {
    let mut sockaddr = MaybeUninit::<libc::sockaddr_storage>::uninit();
    let (sockaddr, len) = unsafe {
        match addr {
            SocketAddr::V4(addr) => {
                let mut in_s: libc::sockaddr_in = mem::zeroed();
                in_s.sin_family = libc::AF_INET as libc::sa_family_t;
                in_s.sin_addr = to_in_addr(&addr.ip());
                in_s.sin_port = addr.port().to_be();
                ptr::copy_nonoverlapping(&in_s, sockaddr.as_mut_ptr().cast(), 1);
                (sockaddr.assume_init(), mem::size_of::<libc::sockaddr_in>())
            }
            SocketAddr::V6(addr) => {
                let mut in6_s: libc::sockaddr_in6 = mem::zeroed();
                in6_s.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                in6_s.sin6_addr = to_in6_addr(&addr.ip());
                in6_s.sin6_port = addr.port().to_be();
                ptr::copy_nonoverlapping(&in6_s, sockaddr.as_mut_ptr().cast(), 1);
                (sockaddr.assume_init(), mem::size_of::<libc::sockaddr_in6>())
            }
        }
    };
    syscall!(sendto(
        sock,
        buf.as_ptr().cast(),
        buf.len(),
        flags,
        (&sockaddr) as *const _ as _,
        len as libc::socklen_t
    ))
    .map(|n| n as usize)
}

pub(crate) fn to_in_addr(addr: &Ipv4Addr) -> libc::in_addr {
    libc::in_addr {
        s_addr: u32::from_ne_bytes(addr.octets()),
    }
}

pub(crate) fn from_in_addr(addr: libc::in_addr) -> Ipv4Addr {
    Ipv4Addr::from(addr.s_addr.to_ne_bytes())
}

pub(crate) fn to_in6_addr(addr: &Ipv6Addr) -> libc::in6_addr {
    libc::in6_addr {
        s6_addr: addr.octets(),
    }
}

pub(crate) fn from_in6_addr(addr: libc::in6_addr) -> Ipv6Addr {
    Ipv6Addr::from(addr.s6_addr)
}

impl crate::socket::Socket {
    #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
    pub(crate) fn bind_device(&self, interface: Option<&[u8]>) -> io::Result<()> {
        let (value, len) = if let Some(interface) = interface {
            (interface.as_ptr(), interface.len())
        } else {
            (ptr::null(), 0)
        };

        syscall!(setsockopt(
            self.as_raw(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            value.cast(),
            len as libc::socklen_t
        ))
        .map(|_| ())
    }

    pub(crate) fn _set_cloexec(&self, close_on_exec: bool) -> io::Result<()> {
        if close_on_exec {
            fcntl_add(
                self.as_raw(),
                libc::F_GETFD,
                libc::F_SETFD,
                libc::FD_CLOEXEC,
            )
        } else {
            fcntl_remove(
                self.as_raw(),
                libc::F_GETFD,
                libc::F_SETFD,
                libc::FD_CLOEXEC,
            )
        }
    }

    #[cfg(target_vendor = "apple")]
    pub(crate) fn _set_nosigpipe(&self, nosigpipe: bool) -> io::Result<()> {
        setsockopt(
            self.as_raw(),
            libc::SOL_SOCKET,
            libc::SO_NOSIGPIPE,
            nosigpipe as c_int,
        )
    }
}
