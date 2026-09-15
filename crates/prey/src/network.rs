//! # Network Module
//! The Network Module of PREY framework contains all the communication of user's code and the network.
//! It defines what is a connection and deals with it: Opening, managing and shutting down.
//! 
//! # How to use this module properly
//! 
//! ## RawSockets
//! 
//! So the first thing you want to do is to define what's your aplication IP. Then you'll create a new
//! `SocketAddr::V4` object, for you RawSocket.
//! 
//! # Code Example
//! ```rust
//!     let addr = SocketAddr::V4(SocketAddrV4::new(188.20.57.2, 8080)); // Returns a SocketAddr object
//!     let socket = RawSocket::new("prey-tap0", "188.20.57.1/24", "2006:abc::1/64").unwrap(); // Creates RawSocket
//!     let pool = BufferPool::new(10); // Initializes bufferpool
//!     let tx = pool.acquire().unwrap(); // Buffer acquiring (write_buffer)
//!     let rx = pool.acquire().unwrap(); // Buffer acquiring (read_buffer)
//!     let mut conn = Connection::new(socket, addr, tx, rx).unwrap(); // Creating connection
//! 
//!     loop { // Listening loop
//!         match conn.receive() { // Receiving data
//!             Ok(0) => {}, // Does nothing
//!             Err(e) if e.kind() == ErrorKind::WouldBlock => {}, // Does nothing
//!             Err(e) => { // Default internal error treatment
//!                 log!("Error while receiving data: {}", e);
//!                 conn.read_buffer.clear();
//!             },
//!             Ok(n) => { // Data processing
//!                 println!("Received {} bytes of data!", n);
//!                 [...] // Data processing
//!             }
//!         }
//!     }
//! ```
#[cfg(target_os = "linux")]
use std::fs::{File, OpenOptions};
use std::net::{TcpStream, SocketAddr};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use crate::buffer::Buffer;
use libc::{F_GETFL, F_SETFL, O_NONBLOCK};
use std::os::unix::io::RawFd;
use std::process::{Command, Stdio};
use std::error::Error;

const TUNSETIFF: libc::c_ulong = 0x400454ca;
const IFF_TAP: libc::c_short = 0x0002;
const IFF_NO_PI: libc::c_short = 0x1000;

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
    /// 
    /// # Usage
    /// ```rust
    ///     let write_buffer = pool.acquire();
    ///     let read_buffer = pool.acquire();
    ///     
    ///     let conn = Connection::new(CONN, write_buffer, read_buffer) // returns a new Connection object.
    ///     // CONN is the conection type, which can be a TcpStream or a RawSocket.
    /// ```
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
    /// 
    /// # Usage
    /// - Optimaly, done inside a `loop {}`
    /// ```rust
    ///     match conn.receive() {
    ///         Ok(0) => {}, // Does nothing
    ///         Ok(n) => {
    ///             [...] // Data processing
    ///         },
    ///         Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}, // Does nothing
    ///         Err(e) => {
    ///             [...] // Internal error tratments
    ///         }
    ///     }
    /// ```
    /// 
    /// - **IMPORTANT**: After the end of data processing, you **need** to clear `conn.read_buffer`, so when you receive
    /// more data, the buffer will not be carrying the already processed data too.
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
    /// 
    /// # Usage
    /// ```rust
    ///     let wb = conn.write_buffer.as_mut_slice(); // Get Connection's `write_buffer` empty space for writing
    ///     wb[..content.len()].copy_from_slice(&content); // Writing `content` at `conn.write_buffer` (wb)
    ///     conn.write_buffer.advance(content.len() as usize); // Increasing filled data segment of `conn.write_buffer`
    ///     conn.send().unwrap(); // Attempts to send message and if succeeded, automatically clears `conn.write_buffer`
    /// ```
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
    pub fd: RawFd,
    pub tap_file: File
}

impl RawSocket {
    /// # fn new
    /// Function that creates a new RawSocket, interacting directly with the Linux Kernel.
    ///
    /// # Params
    /// - interface: `&str` - The interface name which will be used by the RawSocket.
    /// - sub_networkv4: `&str` - A IPv4 sub-network ("199.215.25.1/24") where the RawSocket will 
    /// listen for IPv4 packets.
    /// - sub_networkv6: `&str` - A IPv6 sub-network ("2000:ab2::1/64") where the Raw Socket will
    /// listen for IPv6 packets. 
    /// 
    /// # Returns
    /// A `Result` containing the RawSocket object.
    /// 
    /// # Usage
    /// ```rust
    ///     let sock = RawSocket::new("prey-tap0", "192.168.144.1/24", "abcd::2006::1/64") // Will create a new socket at `prey-tap0` interface, with IPv4 and IPv6 passed as params
    /// ```
    pub fn new(interface: &str, sub_networkv4: &str, sub_networkv6: &str) -> io::Result<Self> {
        setup_tap_interface(interface, sub_networkv4, sub_networkv6).unwrap();

        let tap_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")?;

        let mut ifr: Ifreq = unsafe { std::mem::zeroed() };
        
        let name_bytes = "prey-tap0".as_bytes();
        let len = std::cmp::min(name_bytes.len(), 15);
        ifr.ifr_name[..len].copy_from_slice(&name_bytes[..len]);
        ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

        unsafe {
            if libc::ioctl(tap_file.as_raw_fd(), TUNSETIFF, &ifr) < 0 {
                return Err(io::Error::last_os_error());
            }
        }

        let fd = tap_file.as_raw_fd();
        unsafe {

            let flags = libc::fcntl(fd, F_GETFL, 0);
            if flags < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            if libc::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0 {
                let err = io::Error::last_os_error();
                libc::close(fd);
                return Err(err);
            }

            Ok(Self { fd, tap_file })
        }
    }
}

impl Read for RawSocket {
    //Read implementation for the PREY Raw socket to read directly from the network board.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.tap_file.read(buf) {
            Ok(n) => Ok(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Err(e),
            Err(e) => Err(e) 
        }
    }
}

impl Write for RawSocket {
    //Write implementation for PREY Raw socket to write directly on network board.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.tap_file.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tap_file.flush()
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

/// # Ifreq
/// Struct that represents a Interface Request for kernel creation and usage of tap0.
/// 
/// # Fields
/// - ifr_name: `[u8; 16]` - Interface name
/// - ifr_flags: `libc::c_short` - Interface flags
/// - _pad: `[u8; 22]` - Padding to match original C struct
#[repr(C)]
struct Ifreq {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

/// # fn setup_tap_interface
/// Function that creates and do basic tap0 configuration, eliminating the need of typing
/// commands manually.
/// 
/// # Params
/// - sub_networkv4: `String` - The subnetwork tap0 should work on (ex: 172.16.50.1/24)
/// 
/// # Returns
/// A `Result<(), Box<dyn Error>>` that represents the success or not of the tap interface (name: 'prey-tap0') creation.
/// 
/// # Usage
/// This is a private function, only being used by `RawSocket::new([...])`!
fn setup_tap_interface(interface: &str, sub_networkv4: &str, sub_networkv6: &str) -> Result<(), Box<dyn Error>> {

    let exists = Command::new("ip")
        .args(["link", "show", interface])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success();

    if !exists {
        println!("[PREY] :: creating {} interface.", interface);
        Command::new("sudo").args(["ip", "tuntap", "add", "mode", "tap", interface]).status()?;
    } else {
        println!("[PREY] :: {} already exists.", interface);
    }

    let ip_output = Command::new("sudo")
        .args(["ip", "addr", "add", sub_networkv4, "dev", interface])
        .stderr(Stdio::piped()) 
        .output()?;

    if !ip_output.status.success() {
        let err_msg = String::from_utf8_lossy(&ip_output.stderr);
        if err_msg.contains("File exists") {
            println!("[PREY] :: IPv4 of {} is already addressed.", interface);
        } else {
            eprintln!("[PREY] :: error setting IPv4: {}", err_msg.trim());
        }
    }

    let output = Command::new("sudo")
        .args(["ip", "-6", "addr", "add", sub_networkv6, "dev", interface])
        .stderr(Stdio::piped())
        .output()?;

    if !output.status.success() {
        let err_msg = String::from_utf8_lossy(&output.stderr);
        if err_msg.contains("File exists") {
            println!("[PREY] :: IPv6 of {} is already addressed.", interface);
        } else {
            eprintln!("[PREY] :: error setting IPv6: {}", err_msg.trim());
        }
    }

    Command::new("sudo")
        .args(["ip", "link", "set", interface, "up"])
        .status()?;

    let base_ip = sub_networkv4.split_once("/").map(|(ip, _)| ip).unwrap_or(sub_networkv4);
    let mut parts: Vec<&str> = base_ip.split('.').collect();
    if parts.len() == 4 {
        parts[3] = "1"; 
    }
    let ip_dest = parts.join(".");

    println!("[PREY] :: routing for {} via {} is active.", ip_dest, interface);
    println!("[PREY] :: {} interface was successfully synchronized!", interface);

    Ok(())
}