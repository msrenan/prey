//! # Network Module
//! The Network Module of PREY framework contains all the comunication of user's code and the network.
//! It defines what is a connection and deals with it: Opening, managing and shuting down.

use std::net::{TcpStream, SocketAddr};
use std::io::{self, Read, Write};
use crate::buffer::Buffer;

/// # Connection
/// Struct that contains the structure of a connection of the PREY framework
/// # Fields
/// - stream: `TcpStream` - The stream that holds the connection.
/// - peer_addr: `SocketAddr` - The clients and server IP information.
/// - read_buffer: `Buffer` - Buffer for reading stream data.
/// - write_buffer: `Buffer` - Buffer for writing data on stream.
pub struct Connection {
    pub stream: TcpStream,
    pub peer_addr: SocketAddr,
    pub read_buffer: Buffer,
    pub write_buffer: Buffer
}

impl Connection {
    /// # fn new
    /// Function that creates a new Connection.
    ///
    /// # Params
    /// - stream: `TcpStream` - The stream that holds the connection.
    /// - addr: `SocketAddr` - The IP addresses of client and server.
    /// - wb: `Buffer` - Connection's write buffer.
    /// - rb: `Buffer` - Connection's read buffer.
    ///
    /// # Returns
    /// A `Result` of containing the Connection object.
    pub fn new(stream: TcpStream, addr: SocketAddr, wb: Buffer, rb: Buffer) -> io::Result<Self> {
        stream.set_nonblocking(true)?;
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
    /// - **Ok(1)** - If the client is connected, but sent nothing.
    /// - **Err(e)** - If some error *e* have happened.
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
                Ok(1)
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