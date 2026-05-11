//! # Packet module
//! The Packet module of PREY framework contains all the packet and stream interpreting information
//! that came from the stream or from the raw socket. It defines what is a packet and how to deal with
//! it.

use std::fmt;
//To-do -> Checksums

/// # RawPacket
/// Struct that holds a pointer for the raw bytes of a packet in a buffer.
///
/// ### Lifetime <'a>
/// Used a lifetime so a raw packet pointing to a buffer lasts only while the buffer lasts too.
///
/// # Fields
/// - raw: `&'a [u8]` - Pointer to the raw bytes of the packet within a buffer.
pub struct Packet<'a> {
    pub raw: &'a [u8]
}

impl<'a> Packet<'a> {

    /// # fn new
    /// Function that creates a new Packet.
    ///
    /// # Params
    /// - raw: `&'a [u8]` - The raw bytes of the Packet.
    ///
    /// # Returns
    /// A new Packet Object.
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw }
    }

    /// # fn len
    /// Function that gets the total length of the packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// The total length of the packet.
    pub fn len(&self) -> usize {
        self.raw.len()
    }

    /// # fn is_empty
    /// Function that checks if a Packet is empty.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// **True** if the packet is empty, **False** if it's not.
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// # fn ethernet_header
    /// Function that parses the packet to extract the **ethernet header**.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// A `Result` containing a *EthernetHeader* object or a static error message.
    pub fn ethernet_header(&self) -> Result<EthernetHeader, &'static str> {
        EthernetHeader::parse(self.raw)
    }
}

/// # EtherType
/// Enum that contains the possible ethernet connection types.
/// # Types
/// - IPv4
/// - IPv6
/// - ARP
/// - Unknown - used for unmapped types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Unknown(u16)
}

impl From<u16> for EtherType {
    //Implementation of trait from to EtherType for initializing
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x86DD => EtherType::IPv6,
            0x0806 => EtherType::ARP,
            _ => EtherType::Unknown(value)
        }
    }
}

impl fmt::Display for EtherType {
    //Implementation of trait display to EtherType for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::IPv4 => write!(f, "IPv4"),
            EtherType::IPv6 => write!(f, "IPv6"),
            EtherType::ARP => write!(f, "ARP"),
            EtherType::Unknown(val) => write!(f, "Unknown type: (0x{:04X})", val),
        }
    }
}

/// # EthernetHeader
/// Struct that contains all Ethernet Header information.
///
/// # Fields
/// - dst_mac: `[u8; 6]` - A array of 6 bytes that represents the Destination MAC address.
/// - src_mac: `[u8; 6]` - A array of 6 bytes that represents the Source MAC address.
/// - ether_type: `EtherType` - The ethernet connection type, mapped by the **EtherType enum**.
#[derive(Debug, Clone, Copy)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: EtherType
}

impl EthernetHeader {
    /// # fn parse
    /// Extract the ethernet header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new EthernetHeader object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 14 {
            return Err("Packet is too short to have an Ethernet Header.");
        }

        let mut dst_mac = [0u8; 6];
        dst_mac.copy_from_slice(&raw[0..6]);

        let mut src_mac = [0u8; 6];
        src_mac.copy_from_slice(&raw[6..12]);

        let eth_type = EtherType::from(u16::from_be_bytes([raw[12], raw[13]]));

        Ok(Self {
            dst_mac,
            src_mac,
            ether_type: eth_type
        })
    }
}

impl fmt::Display for EthernetHeader {
    //Implementation of fmt::Display trait for EthernetHeader for better viewing.
    fn fmt(&self, f:&mut fmt::Formatter<'_>) -> fmt::Result {
        let dst = self.dst_mac;
        let dst_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);

        let src = self.src_mac;
        let src_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                              src[0], src[1], src[2], src[3], src[4], src[5]);

        write!(
            f,
            "Ethernet Header {{Destiny MAC: {}, Source MAC: {}, EthernetType: {} }}",
            dst_str, src_str, self.ether_type
        )
    }
}

