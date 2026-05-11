//! # Packet module
//! The Packet module of PREY framework contains all the packet and stream interpreting information
//! that came from the stream or from the raw socket. It defines what is a packet and how to deal with
//! it.

use std::{fmt, net::{Ipv4Addr, Ipv6Addr}};

/// # Packet
/// Struct that holds a pointer for the raw bytes of a packet in a buffer.
///
/// ### Lifetime <'a>
/// Used a lifetime so a raw packet pointing to a buffer lasts only while the buffer lasts too.
///
/// # Fields
/// - raw: `&'a [u8]` - Pointer to the raw bytes of the packet within a buffer.
#[derive(Clone, Copy, Debug)]
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
}


/// # EtherType
/// Enum that contains all possibilites of ethernet type of a packet.
/// 
/// # Types
/// - IPv4
/// - IPv6
/// - ARP
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP
}

/// # EthernetHeader
/// Struct that defines and separate all information of packet's ethernet header.
/// 
/// # Fields
/// - dst_mac: `[u8; 6]` - Destination MAC address
/// - src_mac: `[u8; 6]` - Source MAC address
/// - ether_type: `EtherType` - Ethernet Connection Type
#[derive(Clone, Copy, Debug)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: EtherType
}


/// # IpProtocol
/// Enum that contains all possibilities of packet's protocol.
/// 
/// # Types
/// - TCP
/// - UDP
/// - ICMP
/// - Unknown(`u8`) - Special type, further customization or expansion of the framework
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpProtocol {
    TCP,
    UDP,
    ICMP,
    Unknown(u8)
}

/// # IPv4Header
/// Struct that defines and separate all information of packet's IPv4 Header.
/// 
/// # Fields
/// - version_and_ihl: `u8` - Version of IP and In Header Length
/// - tos: `u8` - Type of Service
/// - total_len: `u16` - Total length (payload + ihl)
/// - id: `u16` - Identification
/// - flags: `u16` - Flags
/// - ttl: `u8` - Time to Live
/// - protocol: `IpProtocol` - Packet's protocol
/// - checksum: `u16` - Checksum value
/// - src_ip: `Ipv4Addr` - Source IP
/// - dst_ip: `Ipv4Addr` - Destination IP
#[derive(Clone, Copy, Debug)]
pub struct IPv4Header {
    pub version_and_ihl: u8,
    pub tos: u8,
    pub total_len: u16,
    pub id: u16,
    pub flags: u16,
    pub ttl: u8,
    pub protocol: IpProtocol,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr
}

/// # IPv6Header
/// Struct that defines and separates all information of packet's IPv6 Header.
/// 
/// # Fields
/// - vcf: `u32` - Version, Class and FlowLevel
/// - payload_length: `u16` - Payload Length
/// - next_header: `IpProtocol` - Packet's protocol
/// - hop_limit: `u8` - Hop Limit (ipv6 ttl)
/// - src_ip: `Ipv6Addr` - Source IP
/// - dst_ip: `Ipv6Addr` - Destination IP
#[derive(Clone, Copy, Debug)]
pub struct IPv6Header {
    pub vcf: u32,
    pub payload_length: u16,
    pub next_header: IpProtocol,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr
}

/// # ArpOperation
/// Enum containing all possibilities for a ARP package operation, based on its opcode.
/// 
/// # Types
/// - Request
/// - Reply
/// - RRequest - Reverse Request (RARP Request)
/// - RReply - Reverse Reply (RARP Reply)
/// - IRequest - Inverted Request
/// - IReply - Inverted Reply
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArpOperation {
    Request,
    Reply,
    RRequest,
    RReply,
    IRequest,
    IReply
}

/// # ArpHeader
/// Struct that defines and separates all information of packet's ARP Header.
/// 
/// # Fields
/// - hw_type: `u16` - Hardware Type
/// - protocol_type: `u16` - Protocol type
/// - hw_size: `u8` - Hardware Size
/// - protocol_size: `u8` - Protocol Size
/// - op: `ArpOperation` - Operation
/// - snd_mac: `[u8; 6]` - Sender's MAC address
/// - snd_ip: `u32` - Sender's IP
/// - tgt_mac: `[u8; 6]` - Target's MAC address
/// - tgt_ip: `u32` - Target's IP
#[derive(Clone, Copy, Debug)]
pub struct ArpHeader {
    pub hw_type: u16,
    pub protocol_type: u16,
    pub hw_size: u8,
    pub protocol_size: u8,
    pub op: ArpOperation,
    pub snd_mac: [u8; 6],
    pub snd_ip: u32,
    pub tgt_mac: [u8; 6],
    pub tgt_ip: u32
}

/// # UdpHeader
/// Struct that defines and separates all information of packet's UDP Header.
/// 
/// # Fields
/// - src_port: `u16` - Source Port
/// - dst_port: `u16` - Destination Port
/// - length: `u16` - Length
/// - checksum: `u16` - Checksum value
#[derive(Clone, Copy, Debug)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

/// # TcpHeader
/// Struct that defines and separates all information of packet's TCP Header.
/// 
/// # Fields
/// - src_port: `u16` - Source Port
/// - dst_port: `u16` - Destination Port
/// - seq_number: `u32` - Sequence Number
/// - ack_number: `u32` - Acknoledgement Number
/// - data_offset: `u8` - Offset to the start of the payload
/// - flags: `u8` - Flags
/// - window_size: `u16` - Window Size
/// - checksum: `u16` - Checksum value
/// - urgent_pointer: `u16` - Urgent Pointer
#[derive(Clone, Copy, Debug)]
pub struct TcpHeader{
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16
}

/// # IcmpHeader
/// Struct that defines and separates all information of packet's TCP Header.
/// 
/// # Fields
/// - icmp_type: `u8` - Type
/// - code: `u8` - Code
/// - checksum: `u16` - Checksum value
/// - id: `u16` - Identification
/// - seq_number: `u16` - Sequence number
#[derive(Clone, Copy, Debug)]
pub struct IcmpHeader {
    pub icmp_type: u8,
    pub code: u8,
    pub checksum: u16,
    pub id: u16,
    pub seq_number: u16
}

/// # L3
/// Enum that contains all possible L3 Headers.
/// 
/// # Types
/// - IPv4(IPv4Header, IpProtocol) - holds the IPv4Header and Protocol of the packet to ease some processes
/// - IPv6(IPv6Header, IpProtocol) - holds the IPv6Header and Protocol of the packet to ease some processes
/// - ARP(ArpHeader) - holds only the ArpHeader because does not have anything relevant besides it
pub enum L3 {
    IPv4(IPv4Header, IpProtocol),
    IPv6(IPv6Header, IpProtocol),
    ARP(ArpHeader)
}

/// # L4
/// Enum that contains all possible L4 Headers.
/// 
/// # Types
/// - TCP(TcpHeader) - holds the TcpHeader of the packet to ease some processes
/// - UDP(UdpHeader) - holds the UdpHeader of the packet to ease some processes
/// - ICMP(IcmpHeader) - holds the IcmpHeader of the packet to ease some processes
/// - Raw - show that the remaining bytes of the packet are already the payload.
/// - Unknown(u8) - holds the byte that represents the protocol/next_header data of Ipv4/6 Header.
pub enum L4 {
    TCP(TcpHeader),
    UDP(UdpHeader),
    ICMP(IcmpHeader),
    Raw,
    Unknown(u8)
}