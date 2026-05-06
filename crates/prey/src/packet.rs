//! # Packet module
//! The Packet module of PREY framework contains all the packet and stream interpreting information
//! that came from the stream or from the raw socket. It defines what is a packet and how to deal with
//! it.

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
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

    /// # fn payload_after_ethernet
    /// Function that returns the payload after the ethernet header.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// A `Result` containing a **&'a \[u8]** slice of bytes or a static error message.
    pub fn payload_after_ethernet(&self) -> Result<&'a [u8], &'static str> {
        if self.raw.len() < 14 {
            return Err("No ethernet header.");
        }
        Ok(&self.raw[14..])
    }

    /// # fn payload
    /// Function that extract the payload of a Packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated Packet.
    ///
    /// # Returns
    /// A `Result` containing either a `&'a [u8]` reference for the slice of bytes within the buffer that
    /// represents the payload or either a static error message.
    pub fn payload(&self) -> Result<&'a [u8], &'static str> {
        let eth = EthernetHeader::parse(self.raw)?;
        let raw = self.payload_after_ethernet()?;
        let mut current_offset = 0;
        let mut ipv4 = Ipv4Header::null();
        let mut ipv6 = Ipv6Header::null();

        let protocol = match eth.ether_type {
            EtherType::IPv4 => {
                ipv4 = Ipv4Header::parse(&raw[current_offset..])?;
                current_offset += ipv4.length as usize;
                ipv4.protocol
            },
            EtherType::IPv6 => {
                ipv6 = Ipv6Header::parse(&raw[current_offset..])?;
                current_offset += 40;
                ipv6.next_header
            },
            EtherType::ARP => {
                let arp = ARPHeader::parse(&raw[current_offset..]);
                current_offset += 20;
                return Ok(&raw[current_offset..]);
            }
            _ => return Ok(&raw[current_offset..])
        };

        match protocol {
            IpProtocol::TCP => {
                if ipv4.version == 4 {
                    if !validate_l4_checksum_ipv4(ipv4, &raw[current_offset..]) {
                        return Err("Packet Corrupted: Invalid TCP Checksum");
                    }
                } else if ipv6.version == 6 {
                    if !validate_l4_checksum_ipv6(ipv6, &raw[current_offset..]) {
                        return Err("Packet Corrupted: Invalid TCP Checksum");
                    }
                }
                let tcp = TCPHeader::parse(&raw[current_offset..])?;
                current_offset += tcp.data_offset as usize;
            },
            IpProtocol::UDP => {
                if ipv4.version == 4 {
                    if !validate_l4_checksum_ipv4(ipv4, &raw[current_offset..]) {
                        return Err("Packet Corrupted: Invalid UDP Checksum.");
                    }
                } else if ipv6.version == 6 {
                    if !validate_l4_checksum_ipv6(ipv6, &raw[current_offset..]) {
                        return Err("Packet Corrupted: Invalid TCP Checksum");
                    }
                }
                let udp = UDPHeader::parse(&raw[current_offset..])?;
                current_offset += 8;
            },
            _ => {}
        }

        if current_offset <= self.raw.len() {
            Ok(&raw[current_offset..])
        } else {
            Err("Packet have been compromised: Headers length surpass total packet length.")
        }
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

/// # IpProtocol
/// Enum that contains the possible IP protocols types
/// # Types
/// - ICMP
/// - TCP
/// - UDP
/// - Unknown(u8) - used for unmapped protocols.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    ICMP,
    TCP,
    UDP,
    Unknown(u8)
}

impl From<u8> for IpProtocol {
    //Implementation of trait from to IpProtocol for initializing
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::ICMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            _ => IpProtocol::Unknown(value)
        }
    }
}

impl fmt::Display for IpProtocol {
    //Implementation of trait display to EtherType for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpProtocol::ICMP => write!(f, "ICMP"),
            IpProtocol::TCP => write!(f, "TCP"),
            IpProtocol::UDP => write!(f, "UDP"),
            IpProtocol::Unknown(val) => write!(f, "Unknown ({})", val),
        }
    }
}

/// # Ipv4Header
/// Struct containing all IPv4 Header information.
///
/// # Fields
/// - version: `u8` - A byte that represents the IP version.
/// - length: `u8` - A byte that represents the header length.
/// - total_length: `u8` - A half-word that represents the total length of the next layers of the packet.
/// - ttl: `u8` - A byte that represents the Packet's **Time-to-Live**.
/// - protocol: `IpProtocol` - The IP protocol of the packet, mapped by **IpProtocol enum**.
/// - checksum: `u16` - The IPv4 Header's checksum value.
/// - src_ip: `Ipv4Addr` - The packet's source IP.
/// - dst_ip: `Ipv4Addr` - The packet's destination IP.
#[derive(Debug, Clone, Copy)]
pub struct Ipv4Header {
    pub version: u8,
    pub length: u8,
    pub total_length: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr
}

impl Ipv4Header {
    /// # fn parse
    /// Extract the IPv4 header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new Ipv4Header object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 20 {
            return Err("Packet is too short to be IPv4.");
        }

        let version = raw[0] >> 4;
        let length = (raw[0] & 0x0F) * 4;

        if raw.len() < length as usize {
            return Err("Packet have been compromised.");
        }

        let hb = &raw[..length as usize];
        if calculate_checksum(hb) != 0 {
            return Err("Corrupted Packet: Invalid IPv4 Checksum");
        }

        let total_length = u16::from_be_bytes([raw[2], raw[3]]);
        let ttl = raw[8];
        let protocol = IpProtocol::from(raw[9]);

        let checksum = u16::from_be_bytes([raw[10], raw[11]]);

        let src_ip = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
        let dst_ip = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);

        Ok( Self {
            version,
            length,
            total_length,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip
        } )
    }

    pub fn null() -> Self {
        Self {
            protocol: IpProtocol::Unknown(0),
            version: 0,
            length: 0,
            total_length: 0,
            ttl: 0,
            src_ip: Ipv4Addr::from_bits(0),
            dst_ip: Ipv4Addr::from_bits(0),
            checksum: 0
        }
    }
}

impl fmt::Display for Ipv4Header {
    //Implementation of trait display to Ipv4Header for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4 {{ Source: {}, Destiny: {}, Protocol: {}, TTL: {}, Total Length: {} }}",
            self.src_ip, self.dst_ip, self.protocol, self.ttl, self.total_length
        )
    }
}

/// # Ipv6Header
/// Struct containing all IPv6 Header information.
///
/// # Fields
/// - version: `u8` - A byte that represents the IP version.
/// - payload_length: `u16` - A half-word that represents the total length of packet's next layers.
/// - next_header: `IpProtocol` - The IP protocol of the packet, mapped by **IpProtocol enum**.
/// - src_ip: `Ipv6Addr` - The packet's source IP.
/// - dst_ip: `Ipv6Addr` - The packet's destination IP.
#[derive(Debug, Clone, Copy)]
pub struct Ipv6Header {
    pub version: u8,
    pub payload_length: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr
}

impl Ipv6Header {
    /// # fn parse
    /// Extract the IPv6 header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new Ipv6Header object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 40 {
            return Err("Packet is too short to be IPv6.");
        }

        let version = raw[0] >> 4;
        let payload_length = u16::from_be_bytes([raw[4], raw[5]]);
        let next_header = IpProtocol::from(raw[6]);
        let hop_limit = raw[7];

        let mut src_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&raw[8..24]);

        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&raw[24..40]);

        Ok(Self {
            version,
            payload_length,
            next_header,
            hop_limit,
            src_ip: Ipv6Addr::from(src_bytes),
            dst_ip: Ipv6Addr::from(dst_bytes)
        })
    }

    pub fn null() -> Self {
        Self {
            version: 0,
            payload_length: 0,
            next_header: IpProtocol::Unknown(0),
            hop_limit: 0,
            src_ip: Ipv6Addr::from_bits(0),
            dst_ip: Ipv6Addr::from_bits(0)
        }
    }
}

impl fmt::Display for Ipv6Header {
    //Implementation of trait display to Ipv6Header for displaying it on screen.

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv6 {{ Source: {}, Destiny: {}, Hop Limit: {}, Payload Length: {}, Next Header: {} }}",
            self.src_ip, self.dst_ip, self.hop_limit, self.payload_length, self.next_header
        )
    }
}

/// # UDPHeader
/// Struct containing all UDP header information.
///
/// # Fields
/// - src_port: `u16` - A half-word that represents the packet's source port.
/// - dst_port: `u16` - A half-word that represents the packet's destination port.
/// - length: `u16` - A half-word that represents the header's length.
/// - checksum: `u16` - The header's **checksum** value.
#[derive(Debug, Clone, Copy)]
pub struct UDPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16
}

impl UDPHeader {
    /// # fn parse
    /// Extract the UDP header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new UDPHeader object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 8 {
            return Err("Packet is too short to be an UDP packet.");
        }

        Ok(Self {
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            length: u16::from_be_bytes([raw[4], raw[5]]),
            checksum: u16::from_be_bytes([raw[6], raw[7]])
        })
    }
}

impl fmt::Display for UDPHeader {
    //Implementation of trait display to UDPHeader for displaying it on screen.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UDP {{ Source Port: {}, Destiny Port: {}, Length: {} bytes }}",
            self.src_port, self.dst_port, self.length
        )
    }
}

/// # TCPHeader
/// Struct containing all TCP header information.
///
/// # Fields
/// - src_port: `u16` - A half-word that represents the packet's source port.
/// - dst_port: `u16` - A half-word that represents the packet's destination port.
/// - seq_number: `u32` - A word that represents the packet's sequence number.
/// - ack_number: `u32` - A word that represents the packet's acknowledgement number.
/// - data_offset: `u8` - A byte that represents a offset to the start of packet's payload.
/// - flags: `u16` - A half-word that represents packet's flags.
/// - window_size: `u16` - A half-word that represents the sender's window size.
/// - checksum: `u16` - The header's **checksum** value.
/// - urgent_pointer: `u16` - A half-word that represents the end offset of urgent data.
#[derive(Debug, Clone, Copy)]
pub struct TCPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number:u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16
}

impl TCPHeader {
    /// # fn parse
    /// Extract the TCP header from a packet.
    ///
    /// # Params
    /// - raw: `&[u8] - A reference to the raw packet's bytes.
    ///
    /// # Returns
    /// A `Result` containing a new TCPHeader object or a static error message.
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 20 {
            return Err("Packet is too short to be TCP.");
        }

        let data_offset = (raw[12] >> 4) * 4;

        if raw.len() < data_offset as usize {
            return Err("Packet have been compromised.");
        }

        let flags = ((raw[12] as u16 & 0x01) << 8) | (raw[13] as u16);

        Ok( Self{
            src_port: u16::from_be_bytes([raw[0], raw[1]]),
            dst_port: u16::from_be_bytes([raw[2], raw[3]]),
            seq_number: u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]),
            ack_number: u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]),
            data_offset,
            flags,
            window_size: u16::from_be_bytes([raw[14], raw[15]]),
            checksum: u16::from_be_bytes([raw[16], raw[17]]),
            urgent_pointer: u16::from_be_bytes([raw[18], raw[19]])
        } )
    }

    /// # fn is_syn
    /// Function that checks if it's a SYN packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `SYN` is active, **False** if it's not.
    pub fn is_syn(&self) -> bool {
        (self.flags & 0x02) != 0
    }

    /// # fn is_ack
    /// Function that checks if it's a ACK packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `ACK` is active, **False** if it's not.
    pub fn is_ack(&self) -> bool {
        (self.flags & 0x10) != 0
    }

    /// # fn is_fin
    /// Function that checks if it's a FIN packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `FIN` is active, **False** if it's not.
    pub fn is_fin(&self) -> bool {
        (self.flags & 0x01) != 0
    }

    /// # fn is_rst
    /// Function that checks if it's a RST packet.
    ///
    /// # Params
    /// - &self - A reference to the manipulated TCPHeader object of a packet.
    ///
    /// # Returns
    /// **True** if the flag `RST` is active, **False** if it's not.
    pub fn is_rst(&self) -> bool {
        (self.flags & 0x04) != 0
    }
}

impl fmt::Display for TCPHeader {
    //Implementation of trait display to TCPHeader for displaying it on screen.

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let mut flags_str = String::new();

        if self.is_syn() { flags_str.push_str("SYN "); }
        if self.is_ack() { flags_str.push_str("ACK "); }
        if self.is_fin() { flags_str.push_str("FIN "); }
        if self.is_rst() { flags_str.push_str("RST "); }

        write!(
            f,
            "TCP {{ Source Port: {}, Destiny Port: {}, Seq Number: {}, Ack Number {}, Flags: [{}] }}",
            self.src_port, self.dst_port, self.seq_number, self.ack_number, flags_str
        )
    }
}

pub struct ICMPHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16
}

impl ICMPHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 8 {
            return Err("Packet is too short too be ICMP.");
        }

        if calculate_checksum(raw) != 0 {
            return Err("Corrupted Packet: Invalid ICMP Checksum.");
        }

        Ok(Self {
            icmp_type: raw[0],
            code: raw[1],
            checksum: u16::from_be_bytes([raw[2], raw[3]])
        })
    }
}

impl fmt::Display for ICMPHeader {
    //Implementation of trait display to ICMPHeader for displaying it on screen.

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "UDP {{ Type: {}, Code: {} }}",
            self.icmp_type, self.code
        )
    }
}

pub fn calculate_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;

    while i < data.len().saturating_sub(1) {
        let word = u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        sum += word;
        i += 2;
    }

    if i < data.len() {
        let word = u16::from_be_bytes([data[i], 0]) as u32;
        sum += word;
    }

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !(sum as u16)
}

fn sum_be_u16_slice(data: &[u8]) -> u32 {
    let mut sum = 0u32;
    let mut i = 0;

    while i < data.len().saturating_sub(1) {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }

    if i < data.len() {
        sum += u16::from_be_bytes([data[i], 0]) as u32;
    }

    sum
}

pub fn validate_l4_checksum_ipv4(v4_header: Ipv4Header, raw: &[u8]) -> bool {
    let src = v4_header.src_ip;
    let dst = v4_header.dst_ip;
    let protocol = v4_header.protocol;

    let mut sum = 0u32;

    let src_octets = src.octets();
    let dst_octets = dst.octets();

    sum += u16::from_be_bytes([src_octets[0], src_octets[1]]) as u32;
    sum += u16::from_be_bytes([src_octets[2], src_octets[3]]) as u32;
    sum += u16::from_be_bytes([dst_octets[0], dst_octets[1]]) as u32;
    sum += u16::from_be_bytes([dst_octets[2], dst_octets[3]]) as u32;

    let proto_val = match protocol {
        IpProtocol::TCP => 6u16,
        IpProtocol::UDP => 17u16,
        _ => 0
    };

    sum += proto_val as u32;

    sum += raw.len() as u32;
    sum += sum_be_u16_slice(raw);

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let final_checksum = !(sum as u16);

    if protocol == IpProtocol::UDP && raw.len() >= 8 {
        let sent_checksum = u16::from_be_bytes([raw[6], raw[7]]);
        if sent_checksum == 0 { return true; }
    }

    final_checksum == 0
}

pub fn validate_l4_checksum_ipv6(v6_header: Ipv6Header, raw: &[u8]) -> bool {
    let src = v6_header.src_ip;
    let dst = v6_header.dst_ip;
    let protocol = v6_header.next_header;

    let mut sum: u32 = 0;

    for &segment in &src.segments() {
        sum += segment as u32;
    }
    for &segment in &dst.segments() {
        sum += segment as u32;
    }

    let len = raw.len() as u32;
    sum += (len >> 16) & 0xFFFF;
    sum += len & 0xFFFF;

    let proto_val = match protocol {
        IpProtocol::TCP => 6u16,
        IpProtocol::UDP => 17u16,
        _ => 0,
    };
    sum += proto_val as u32;

    sum += sum_be_u16_slice(raw);

    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    let final_checksum = !(sum as u16);

    if protocol == IpProtocol::UDP && raw.len() >= 8 {
        let sent_checksum = u16::from_be_bytes([raw[6], raw[7]]);
        if sent_checksum == 0 {
            return false;
        }
    }

    final_checksum == 0
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ARPOperation {
    Request,
    Reply,
    Unknown(u16)
}

impl From<u16> for ARPOperation {
    fn from(value: u16) -> Self {
        match value {
            1 => ARPOperation::Request,
            2 => ARPOperation::Reply,
            _ => ARPOperation::Unknown(value)
        }
    }
}

impl fmt::Display for ARPOperation {
    //Implementation of trait display to ARPOperation for displaying it on screen.

    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ARPOperation::Request => write!(f, "Request"),
            ARPOperation::Reply => write!(f, "Reply"),
            ARPOperation::Unknown(val) => write!(f, "Unknown ({})", val),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ARPHeader {
    pub hw_type: u16,
    pub prt_type: u16,
    pub hw_addr_len: u8,
    pub prt_addr_len: u8,
    pub op: ARPOperation,
    pub snd_hw_addr: [u8; 6],
    pub snd_prt_addr: Ipv4Addr,
    pub tgt_hw_addr: [u8; 6],
    pub tgt_prt_addr: Ipv4Addr,
}

impl ARPHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 28 {
            return Err("Packet is too short to be ARP.");
        }

        let mut snd_hw_addr = [0u8; 6];
        snd_hw_addr.copy_from_slice(&raw[8..14]);

        let snd_prt_addr = Ipv4Addr::new(raw[14], raw[15], raw[16], raw[17]);

        let mut tgt_hw_addr = [0u8; 6];
        tgt_hw_addr.copy_from_slice(&raw[18..24]);

        let tgt_prt_addr = Ipv4Addr::new(raw[24], raw[25], raw[26], raw[27]);

        Ok(Self {
            hw_type: u16::from_be_bytes([raw[0], raw[1]]),
            prt_type: u16::from_be_bytes([raw[2], raw[3]]),
            hw_addr_len: raw[4],
            prt_addr_len: raw[5],
            op: ARPOperation::from(u16::from_be_bytes([raw[6], raw[7]])),
            snd_hw_addr,
            snd_prt_addr,
            tgt_hw_addr,
            tgt_prt_addr,
        })
    }
}

impl fmt::Display for ARPHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sha = self.snd_hw_addr;
        let sha_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                              sha[0], sha[1], sha[2], sha[3], sha[4], sha[5]);

        let tha = self.tgt_hw_addr;
        let tha_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                              tha[0], tha[1], tha[2], tha[3], tha[4], tha[5]);

        write!(
            f,
            "ARP {} {{ Sender: {} ({}), Target: {} ({}) }}",
            self.op, sha_str, self.snd_prt_addr, tha_str, self.tgt_prt_addr
        )
    }
}
