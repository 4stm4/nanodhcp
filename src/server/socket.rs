//! UDP socket setup. Linux-specific bits (SO_BINDTODEVICE) are isolated here
//! behind a small FFI shim so the rest of the server stays portable for tests.

use std::io;
use std::net::UdpSocket;

use crate::config::DhcpConfig;

pub const SERVER_PORT: u16 = 67;
pub const CLIENT_PORT: u16 = 68;

/// Bind `0.0.0.0:67`, enable broadcast, and (on Linux) pin the socket to the
/// configured interface. Binding the port requires root.
pub fn bind(cfg: &DhcpConfig) -> io::Result<UdpSocket> {
    let socket = UdpSocket::bind(("0.0.0.0", SERVER_PORT))?;
    socket.set_broadcast(true)?;

    #[cfg(target_os = "linux")]
    linux::bind_to_device(&socket, &cfg.interface);
    #[cfg(not(target_os = "linux"))]
    let _ = cfg; // SO_BINDTODEVICE is Linux-only; ignore the interface elsewhere.

    Ok(socket)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{c_void, CString};
    use std::net::UdpSocket;
    use std::os::unix::io::AsRawFd;

    const SOL_SOCKET: i32 = 1;
    const SO_BINDTODEVICE: i32 = 25;

    extern "C" {
        fn setsockopt(
            socket: i32,
            level: i32,
            name: i32,
            value: *const c_void,
            option_len: u32,
        ) -> i32;
    }

    /// Best-effort SO_BINDTODEVICE. On failure (e.g. missing privileges) we warn
    /// and continue — a single-NIC host still works bound to 0.0.0.0:67.
    pub fn bind_to_device(socket: &UdpSocket, ifname: &str) {
        let cname = match CString::new(ifname) {
            Ok(c) => c,
            Err(_) => {
                eprintln!(
                    "nanodhcp: warning: interface name '{}' contains a NUL byte",
                    ifname
                );
                return;
            }
        };
        // SAFETY: `cname` outlives the call and we pass its byte length; the fd
        // is valid for the lifetime of the borrowed socket.
        let ret = unsafe {
            setsockopt(
                socket.as_raw_fd(),
                SOL_SOCKET,
                SO_BINDTODEVICE,
                cname.as_ptr() as *const c_void,
                ifname.len() as u32,
            )
        };
        if ret != 0 {
            eprintln!(
                "nanodhcp: warning: SO_BINDTODEVICE({}) failed: {}",
                ifname,
                std::io::Error::last_os_error()
            );
        }
    }
}
