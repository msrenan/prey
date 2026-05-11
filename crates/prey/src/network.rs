//! # Network Module
//! The Network Module of PREY framework contains all the communication of user's code and the network.
//! It defines what is a connection and deals with it: Opening, managing and shutting down.

use std::mem;
#[cfg(target_os = "linux")]
use std::net::{TcpStream, SocketAddr};
use std::io::{self, Read, Write};
use crate::buffer::Buffer;
use libc::{socket, AF_PACKET, SOCK_RAW, fcntl, F_GETFL, F_SETFL, O_NONBLOCK};
use std::os::unix::io::RawFd;
use std::ffi::CString;

/// # Connection
/// Struct that contains the structure of a connection of the PREY framework
/// # Fields
/// - stream: `TcpStream` - The stream that holds the connection.
/// - peer_addr: `SocketAddr` - The clients and server IP information.
/// - read_buffer: `Buffer` - Buffer for reading stream data.
/// - write_buffer: `Buffer` - Buffer for writing data on stream.
pub struct Connection<S> {
    pub stream: S,
    pub peer_addr: SocketAddr,
    pub read_buffer: Buffer,
    pub write_buffer: Buffer
}

impl<S: Read + Write> Connection<S> {
    /// # fn new
    /// Function that creates a new Connection.
    ///
    /// Using generic type *S* to support high-level TCP and low-level Raw Sockets.
    ///
    /// # Params
    /// - stream: `S` - The stream that holds the connection.
    /// - addr: `SocketAddr` - The IP addresses of client and server.
    /// - wb: `Buffer` - Connection's write buffer.
    /// - rb: `Buffer` - Connection's read buffer.
    ///
    /// # Returns
    /// A `Result` of containing the Connection object.
    pub fn new(stream: S, addr: SocketAddr, wb: Buffer, rb: Buffer) -> io::Result<Self> {
        //stream.set_nonblocking(true)?; -> Deve ser feito antes de utilizar essa função, agora.
            Ok(Self {
                stream,
                peer_addr: addr,
                write_buffer: wb,
                read_buffer: rb
            })
    }

    /// # fn receive
    /// Function that try to read data on the Connection's stream.
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated Connection.
    ///
    /// # Returns
    /// - **Ok(0)** - If the client have disconnected.
    /// - **Ok(n)** - If the client have sent some information.
    /// - **Err(e)** - If some error *e* have happened. **Do not forget to handle the *WouldBlock* error (the event loop
    ///                 should do nothing when it happens)**.
    pub fn receive(&mut self) -> io::Result<usize> {
        let space = self.read_buffer.as_mut_slice();

        match self.stream.read(space) {
            Ok(0) => {
                Ok(0)
            },
            Ok(n) => {
                self.read_buffer.advance(n);
                Ok(n)
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Err(e)
            },
            Err(e) => {
                Err(e)
            }
        }
    }

    /// # fn send
    /// Function that try to send data on the Connection's stream.
    ///
    /// # Params
    /// - &mut self - Mutable reference to the manipulated Connection.
    ///
    /// # Returns
    /// - **Ok(0)** - If the Connection's write buffer is empty.
    /// - **Ok(n)** - If the data has been successfully written on stream, with *n* being the amount of
    /// bits written.
    /// - **Err(e)** - If some error *e* have happened.
    pub fn send(&mut self) -> io::Result<usize> {
        let data = self.write_buffer.data();

        if data.is_empty() {
            return Ok(0);
        }

        match self.stream.write(data) {
            Ok(n) => {
                self.stream.flush()?;
                self.write_buffer.clear();
                Ok(n)
            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                Ok(0)
            },
            Err(e) =>{
                Err(e)
            }
        }
    }
}

/// # RawSocket
/// Struct that represents a Raw Socket for PREY framework.
/// # Fields
/// - fd: `RawFd` - file descriptor to the socket file.
pub struct RawSocket {
    pub fd: RawFd
}

impl RawSocket {
    /// # fn new
    /// Function that creates a new RawSocket, interacting directly with the Linux Kernel.
    ///
    /// # Returns
    /// A `Result` containing the RawSocket object.
    pub fn new(interface: &str) -> io::Result<Self> {
        unsafe {
            let protocol = 0x0300 as u16;
            let fd = socket(AF_PACKET, SOCK_RAW, protocol as i32);
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let c_ifname = CString::new(interface).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "Invalid interface name.")
            })?;

            let ifindex = libc::if_nametoindex(c_ifname.as_ptr());

            if ifindex == 0 {
                libc::close(fd);
                return Err(io::Error::new(io::ErrorKind::NotFound, "Network Interface not found!"));
            }

            let mut sll: libc::sockaddr_ll = mem::zeroed();

            sll.sll_family = AF_PACKET as u16;
            sll.sll_protocol = protocol;
            sll.sll_ifindex = ifindex as i32;

            let bind_res = libc::bind(fd, &sll as *const _ as * const libc::sockaddr,
            mem::size_of::<libc::sockaddr_ll>() as u32);

            if bind_res < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            let flags = fcntl(fd, F_GETFL, 0);
            if flags < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            if fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            Ok(Self { fd })
        }
    }
}

impl Read for RawSocket {
    //Read implementation for the PREY Raw socket to read directly from the network board.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        unsafe {
            let ret = libc::recv(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0);

            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::WouldBlock {
                    return Err(err);
                }
                return Err(err);
            }

            Ok(ret as usize)
        }
    }
}

impl Write for RawSocket {
    //Write implementation for PREY Raw socket to write directly on network board.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        unsafe {
            let ret = libc::send(self.fd, buf.as_ptr() as *const libc::c_void, buf.len(), 0);

            if ret < 0 {
                return Err(io::Error::last_os_error());
            }

             Ok(ret as usize)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// # ConnType
/// Enum that contains the two possible types of PREY connections
/// # Types
/// - Tcp(`TcpStream`) - TcpStream used for High-Level TCP.
/// - Raw(`RawSocket`) - RawSocket used for Low-Level connections.
pub enum ConnType {
    Tcp(TcpStream),
    Raw(RawSocket)
}


impl Read for ConnType {
    //Read implementation for both connection types using already made implementations in this module.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            ConnType::Tcp(stream) => stream.read(buf),
            ConnType::Raw(socket) => socket.read(buf)
        }
    }
}

impl Write for ConnType {
    //Write implementation for both connection types using the already made implementations in this module.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            ConnType::Tcp(stream) => stream.write(buf),
            ConnType::Raw(socket) => socket.write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            ConnType::Raw(socket) => socket.flush(),
            ConnType::Tcp(stream) => stream.flush()
        }
    }
}