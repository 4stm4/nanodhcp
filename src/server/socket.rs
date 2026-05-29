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
    if let Err(e) = linux::bind_to_device(&socket, &cfg.interface) {
        if cfg.allow_unbound {
            crate::log_warn!(
                "cannot bind to interface '{}': {} (allow_unbound=true, serving on 0.0.0.0)",
                cfg.interface,
                e
            );
        } else {
            // Fail-fast: serving on the wrong interface is dangerous for an
            // appliance. Opt out explicitly with allow_unbound=true.
            return Err(io::Error::other(format!(
                "cannot bind to interface '{}': {} \
                 (set allow_unbound=true to serve on 0.0.0.0 anyway)",
                cfg.interface, e
            )));
        }
    }
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

    /// Apply SO_BINDTODEVICE. Returns the OS error on failure so the caller can
    /// decide whether that is fatal (see `allow_unbound`).
    pub fn bind_to_device(socket: &UdpSocket, ifname: &str) -> std::io::Result<()> {
        let cname = CString::new(ifname).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "interface name contains a NUL byte",
            )
        })?;
        // SAFETY: `cname` outlives the call; we pass its length including the
        // terminating NUL (the conventional form for SO_BINDTODEVICE). The fd is
        // valid for the lifetime of the borrowed socket.
        let ret = unsafe {
            setsockopt(
                socket.as_raw_fd(),
                SOL_SOCKET,
                SO_BINDTODEVICE,
                cname.as_ptr() as *const c_void,
                cname.as_bytes_with_nul().len() as u32,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
}
