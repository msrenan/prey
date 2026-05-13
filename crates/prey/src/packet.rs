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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

    //ICMP REPLY

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

    pub fn ethernet_header(&self) -> Result<(EthernetHeader, usize), &'static str> {
        match EthernetHeader::parse(self.raw) {
            Ok(h) => Ok((h, 14)),
            Err(e) => Err(e)
        }
    }

    pub fn l3_header(&self) -> Result<(L3, usize), &'static str> {
        let (eth, offset) = self.ethernet_header().unwrap();
        let current_offset = 0 + offset;
        let raw = &self.raw[current_offset..];

        match eth.ether_type {
            EtherType::ARP => Ok((L3::ARP(ArpHeader::parse(raw).unwrap()), 28)),
            EtherType::IPv4 => {
                let ipv4 = IPv4Header::parse(raw).unwrap();
                Ok((L3::IPv4(ipv4, ipv4.protocol), ipv4.ihl as usize))
            },
            EtherType::IPv6 => {
                let ipv6 = IPv6Header::parse(raw).unwrap();
                Ok((L3::IPv6(ipv6, ipv6.next_header), 40))
            },
            EtherType::Unknown(b) => Ok((L3::Unknown(b), 2))
        }
    }

    pub fn l4_header(&self) -> Result<(L4, usize), &'static str> {
        let (_, eth_off) = self.ethernet_header().unwrap();
        let (l3, l3_off) = self.l3_header().unwrap();

        let current_offset = 0 + eth_off + l3_off;

        let raw = &self.raw[current_offset..];

        let protocol = match l3 {
            L3::IPv4(_, p) => p,
            L3::IPv6(_, p) => p,
            L3::ARP(_) => {
                IpProtocol::Unknown(0)
            },
            L3::Unknown(b) => IpProtocol::Unknown(b as u8)
        };

        match protocol {
            IpProtocol::ICMP => Ok((L4::ICMP(IcmpHeader::parse(raw).unwrap()), 8)),
            IpProtocol::TCP => {
                let tcp = TcpHeader::parse(raw).unwrap();
                Ok((L4::TCP(tcp), tcp.data_offset as usize))
            },
            IpProtocol::UDP => Ok((L4::UDP(UdpHeader::parse(raw).unwrap()), 8)),
            IpProtocol::Unknown(n) => Ok((L4::Unknown(n), 0))
        }
    }
    
    pub fn payload(&self) -> Result<&'a [u8], &'static str> {
        let (_, eth_off) = match self.ethernet_header() {
            Ok(x) => x,
            Err(e) => { return Err(e); }
        };
        let (l3, l3_off) = match self.l3_header() {
            Ok(x) => x,
            Err(e) => { return Err(e); }
        };

        match l3 {
            L3::ARP(_) => {
                return Ok(self.raw);
            },
            _ => {}
        }
        

        let (_, l4_off) = match self.l4_header() {
            Ok(x) => x,
            Err(e) => {return Err(e); }
        };

        let current_offset = 0 + eth_off + l3_off + l4_off;

        if self.len() >= current_offset {
            Ok(&self.raw[current_offset..])
        } else {
            println!("Packet is too short ({} | {} [0, {}, {}, {}])", current_offset, self.len(), eth_off, l3_off, l4_off);
            Err("Packet is too short.")
        }
    }

    pub fn build_arp_reply(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        let (eth, _) = self.ethernet_header().unwrap();
        let (l3, _) = self.l3_header().unwrap();
        let arp = match l3 {
            L3::ARP(h) => h,
            _ => { return Err("You can't build an arp reply from a non-arp packet"); }
        };

        let mut packet = Vec::with_capacity(42);

        let r_eth = EthernetHeader {
            src_mac: arp.tgt_mac,
            dst_mac: arp.snd_mac,
            ether_type: EtherType::ARP
        };

        packet.extend_from_slice(&r_eth.serialize());

        let r_arp = ArpHeader {
            hw_type: 0x0001,
            protocol_type: 0x0800,
            hw_size: 0x06,
            protocol_size: 0x04,
            op: ArpOperation::Reply,
            snd_mac: arp.tgt_mac,
            snd_ip: arp.tgt_ip,
            tgt_mac: arp.snd_mac,
            tgt_ip: arp.snd_ip
        };

        packet.extend_from_slice(&r_arp.serialize());

        buf[..packet.len()].copy_from_slice(&packet);
        Ok(packet.len())
    }
}


/// # EtherType
/// Enum that contains all possibilites of ethernet type of a packet.
/// 
/// # Types
/// - IPv4
/// - IPv6
/// - ARP
/// - Unknown(`u16`) - Special type, for further customization or expansion of the framework
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EtherType {
    IPv4,
    IPv6,
    ARP,
    Unknown(u16)
}

/// # EthernetHeader
/// Struct that defines and separate all information of packet's ethernet header.
/// 
/// # Fields
/// - dst_mac: `[u8; 6]` - Destination MAC address
/// - src_mac: `[u8; 6]` - Source MAC address
/// - ether_type: `EtherType` - Ethernet Connection Type
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
/// - Unknown(u8) - Special type, for further customization or expansion of the framework
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
/// - version: `u8` - Version
/// - ihl: `u8` - In Header Length
/// - tos: `u8` - Type of Service
/// - total_len: `u16` - Total length (payload + ihl)
/// - id: `u16` - Identification
/// - flags: `u16` - Flags
/// - ttl: `u8` - Time to Live
/// - protocol: `IpProtocol` - Packet's protocol
/// - checksum: `u16` - Checksum value
/// - src_ip: `Ipv4Addr` - Source IP
/// - dst_ip: `Ipv4Addr` - Destination IP
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IPv4Header {
    pub version: u8,
    pub ihl: u8,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IPv6Header {
    pub version: u8,
    pub class: u8,
    pub flow: u32,
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ArpHeader {
    pub hw_type: u16,
    pub protocol_type: u16,
    pub hw_size: u8,
    pub protocol_size: u8,
    pub op: ArpOperation,
    pub snd_mac: [u8; 6],
    pub snd_ip: Ipv4Addr,
    pub tgt_mac: [u8; 6],
    pub tgt_ip: Ipv4Addr
}

/// # UdpHeader
/// Struct that defines and separates all information of packet's UDP Header.
/// 
/// # Fields
/// - src_port: `u16` - Source Port
/// - dst_port: `u16` - Destination Port
/// - length: `u16` - Length
/// - checksum: `u16` - Checksum value
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IcmpType {
    Request,
    Reply,
    Unknown(u8)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IcmpHeader {
    pub icmp_type: IcmpType,
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
/// - Unknown(u16) - Type created to match the EtherType::Unknown(_)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum L3 {
    IPv4(IPv4Header, IpProtocol),
    IPv6(IPv6Header, IpProtocol),
    ARP(ArpHeader),
    Unknown(u16)
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum L4 {
    TCP(TcpHeader),
    UDP(UdpHeader),
    ICMP(IcmpHeader),
    Raw,
    Unknown(u8)
}

//Trait implementation for PREY structs and enums

impl From<u8> for IpProtocol {
    fn from(value: u8) -> Self {
        match value {
            1 => IpProtocol::ICMP,
            6 => IpProtocol::TCP,
            17 => IpProtocol::UDP,
            58 => IpProtocol::ICMP,
            _ => IpProtocol::Unknown(value)
        }
    }
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => EtherType::IPv4,
            0x86DD => EtherType::IPv6,
            0x0806 => EtherType::ARP,
            _ => EtherType::Unknown(value)
        }
    }
}

impl From<u16> for ArpOperation {
    fn from(value: u16) -> Self {
        match value {
            0x0001 => ArpOperation::Request,
            0x0002 => ArpOperation::Reply,
            0x0003 => ArpOperation::RRequest,
            0x0004 => ArpOperation::RReply,
            0x0008 => ArpOperation::IRequest,
            0x0009 => ArpOperation::IReply,
            _ => ArpOperation::Request
        }
    }
}

impl From<u8> for IcmpType {
    fn from(value: u8) -> Self {
        match value {
            8 => IcmpType::Request,
            0 => IcmpType::Reply,
            _ => IcmpType::Unknown(value)
        }
    }
}

impl fmt::Display for EtherType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EtherType::ARP => write!(f, "ARP"),
            EtherType::IPv4 => write!(f, "IPv4"),
            EtherType::IPv6 => write!(f, "IPv6"),
            EtherType::Unknown(b) => write!(f, "Unknown Ethernet Type, bytes: {:02X}", b)
        }
    }
}

impl fmt::Display for IpProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IpProtocol::TCP => write!(f, "TCP"),
            IpProtocol::UDP => write!(f, "UDP"),
            IpProtocol::ICMP => write!(f, "ICMP"),
            IpProtocol::Unknown(b) => write!(f, "Unknown IP Protocol, bytes: {:02X}", b)
        }
    }
}

impl fmt::Display for ArpOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ArpOperation::Reply => write!(f, "ARP Reply"),
            ArpOperation::Request => write!(f, "ARP Request"),
            ArpOperation::RReply => write!(f, "RARP Reply"),
            ArpOperation::RRequest => write!(f, "RARP Request"),
            ArpOperation::IReply => write!(f, "Inverted ARP Reply"),
            ArpOperation::IRequest => write!(f, "Inverted ARP Request"),
        }
    }
}

impl fmt::Display for IcmpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IcmpType::Reply => write!(f, "Reply"),
            IcmpType::Request => write!(f, "Request"),
            IcmpType::Unknown(b) => write!(f, "Unknown operation ({:02X})", b)
        }
    }
}

impl fmt::Display for EthernetHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let src = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.src_mac[0], self.src_mac[1], self.src_mac[2], self.src_mac[3], self.src_mac[4], self.src_mac[5]
        );

        let dst = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.dst_mac[0], self.dst_mac[1], self.dst_mac[2], self.dst_mac[3], self.dst_mac[4], self.dst_mac[5]
        );

        write!(f, "{{ EthernetHeader: *src_mac={} *dst_mac={} *ether_type={} }}", src, dst, self.ether_type)
    }
}

impl fmt::Display for IPv4Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{{ IPv4Header: *src_ip={} *dst_ip={} *total_len={} *protocol={} }}",
            self.src_ip, self.dst_ip, self.total_len, self.protocol
        )
    }
}

impl fmt::Display for IPv6Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{{ IPv6Header: *src_ip={} *dst_ip={} *payload_length={} *next_header={} }}",
            self.src_ip, self.dst_ip, self.payload_length, self.next_header
        )
    }
}

impl fmt::Display for ArpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {

        let snd = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.snd_mac[0], self.snd_mac[1], self.snd_mac[2], self.snd_mac[3], self.snd_mac[4], self.snd_mac[5]
        );

        let tgt = format!(
            "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
            self.tgt_mac[0], self.tgt_mac[1], self.tgt_mac[2], self.tgt_mac[3], self.tgt_mac[4], self.tgt_mac[5]
        );

        write!(f,
            "{{ ArpHeader: *op={} *protocol_type={} *snd_mac={} *tgt_mac={} *tgt_ip={} }}",
            self.op, self.protocol_type, snd, tgt, self.tgt_ip
        )
    }
}

impl fmt::Display for TcpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{{ TcpHeader: *src_port={} *dst_port={} *flags={} *seq_number={} *ack_number{} }}",
            self.src_port, self.dst_port, self.flags, self.seq_number, self.ack_number
        )
    }
}

impl fmt::Display for UdpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
         write!(f,
            "{{ UdpHeader: *src_port={} *dst_port={} *length={} }}",
            self.src_port, self.dst_port, self.length
         )
    }
}

impl fmt::Display for IcmpHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,
            "{{ IcmpHeader: *icmp_type={} *code={} *seq_number={} }}",
            self.icmp_type, self.code, self.seq_number
        )
    }
}

impl fmt::Display for L3 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L3::IPv4(h, _) => write!(f, "[L3] {}", h),
            L3::IPv6(h, _) => write!(f, "[L3] {}", h),
            L3::ARP(h) => write!(f, "[L3] {}", h),
            L3::Unknown(b) => write!(f, "[L3] Unknown L3 type ({:02X}).", b)
        }
    }
}

impl fmt::Display for L4 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            L4::ICMP(p) => write!(f, "[L4] {}", p),
            L4::TCP(p) => write!(f, "[L4] {}", p),
            L4::UDP(p) => write!(f, "[L4] {}", p),
            L4::Raw => write!(f, "[L4] Raw Bytes."),
            L4::Unknown(b) => write!(f, "[L4] Unknown L4 protocol ({:02X})", b)
        }
    }
}

impl<'a> fmt::Display for Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (eth, _) = self.ethernet_header().unwrap();
        let (l3, _) = match self.l3_header() {
            Ok(x) => x,
            Err(_) => (L3::Unknown(0), 0)
        };
        let (l4, _) = match self.l4_header() {
            Ok(x) => x,
            Err(_) => (L4::Raw, 0)
        };
        let payload: &'a [u8] = self.payload().unwrap();

        write!(f,
            "[[ Packet: {}\n\t{}\n\t{}\n\tPayload: {} ]]",
            eth, l3, l4, String::from_utf8_lossy(payload)
        )
    }
}


impl EthernetHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 14 {
            return Err("Packet is too short to have an Ethernet Header");
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];

        dst_mac.copy_from_slice(&raw[0..6]);
        src_mac.copy_from_slice(&raw[6..12]);

        let ether_type = EtherType::from(u16::from_be_bytes([raw[12], raw[13]]));

        Ok( Self {
            dst_mac,
            src_mac,
            ether_type
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut h_b = Vec::with_capacity(14);

        h_b.extend_from_slice(&self.dst_mac);
        h_b.extend_from_slice(&self.src_mac);
        h_b.extend_from_slice(&EtherType::serialize(EtherType::ARP).to_be_bytes());

        h_b
    }
}

impl ArpHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 28 {
            return Err("Packet is too short to have an ARP Header");
        }

        let hw_type = u16::from_be_bytes([raw[0], raw[1]]);
        let protocol_type = u16::from_be_bytes([raw[2], raw[3]]);
        let hw_size = raw[4];
        let protocol_size = raw[5];
        let op = ArpOperation::from(u16::from_be_bytes([raw[6], raw[7]]));
        let mut snd_mac = [0u8; 6];
        snd_mac.copy_from_slice(&raw[8..14]);
        let snd_ip = Ipv4Addr::new(raw[14], raw[15], raw[16], raw[17]);
        let mut tgt_mac = [0u8; 6];
        tgt_mac.copy_from_slice(&raw[18..24]);
        let tgt_ip = Ipv4Addr::new(raw[24], raw[25], raw[26], raw[27]);

        Ok(Self {
            hw_type,
            protocol_type,
            hw_size,
            protocol_size,
            op,
            snd_ip,
            snd_mac,
            tgt_mac,
            tgt_ip
        })

    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut h_b = Vec::with_capacity(28);

        h_b.extend_from_slice(&self.hw_type.to_be_bytes());
        h_b.extend_from_slice(&self.protocol_type.to_be_bytes());
        h_b.extend_from_slice(&[self.hw_size]);
        h_b.extend_from_slice(&[self.protocol_size]);
        h_b.extend_from_slice(&ArpOperation::serialize(self.op).to_be_bytes());
        h_b.extend_from_slice(&self.snd_mac);
        h_b.extend_from_slice(&self.snd_ip.octets());
        h_b.extend_from_slice(&self.tgt_mac);
        h_b.extend_from_slice(&self.tgt_ip.octets());

        h_b
    }
}

impl IPv4Header {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 20 {
            return Err("Packet is too short to have an IPv4 Header");
        }

        let version = raw[0] >> 4;
        let ihl = (raw[0] & 0x0F) * 4;

        if raw.len() < ihl as usize {
            return Err("Packet have been compromised");
        }

        let check_bytes = &raw[..ihl as usize];
        //Calculo da checksum

        let tos = raw[1];

        let total_len = u16::from_be_bytes([raw[2], raw[3]]);
        let id = u16::from_be_bytes([raw[4], raw[5]]);
        let flags = u16::from_be_bytes([raw[6], raw[7]]);
        let ttl = raw[8];
        let protocol = IpProtocol::from(raw[9]);
        let checksum = u16::from_be_bytes([raw[10], raw[11]]);

        let src_ip = Ipv4Addr::new(raw[12], raw[13], raw[14], raw[15]);
        let dst_ip = Ipv4Addr::new(raw[16], raw[17], raw[18], raw[19]);

        Ok( Self {
            version,
            ihl,
            tos,
            total_len,
            id,
            flags,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip
        })
    }
}

impl IPv6Header {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {

        if raw.len() < 40 {
            return Err("Packet is too short to have an IPv6 Header");
        }

        let vcf = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]);

        let version = raw[0] >> 4;
        let class = (raw[0] & 0x0F) * 4;
        let flow = vcf & 0xFFFFF;
        let payload_length = u16::from_be_bytes([raw[4], raw[5]]);
        let next_header = IpProtocol::from(raw[6]);
        let hop_limit= raw[7];
        let mut src = [0u8; 16];
        src.copy_from_slice(&raw[8..24]);
        let mut dst= [0u8; 16];
        dst.copy_from_slice(&raw[24..40]);
        let src_ip = Ipv6Addr::from(src);
        let dst_ip = Ipv6Addr::from(dst);

        Ok( Self {
            version,
            class,
            flow,
            payload_length,
            next_header,
            hop_limit,
            src_ip,
            dst_ip
        })
    }
}

impl IcmpHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {

        if raw.len() < 8 {
            return Err("Packet is too short to have an ICMP Header");
        }

        //Calcular checksum com raw.

        let icmp_type = IcmpType::from(raw[0]);
        let code = raw[1];
        let checksum = u16::from_be_bytes([raw[2], raw[3]]);
        let id = u16::from_be_bytes([raw[4], raw[5]]);
        let seq_number = u16::from_be_bytes([raw[6], raw[7]]);

        Ok(Self {
            icmp_type,
            code,
            checksum,
            id,
            seq_number
        })
    }
}

impl UdpHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 8 {
            return Err("This packet is too short to have an UDP Header");
        }

        let src_port = u16::from_be_bytes([raw[0], raw[1]]);
        let dst_port = u16::from_be_bytes([raw[2], raw[3]]);
        let length = u16::from_be_bytes([raw[4], raw[5]]);
        let checksum = u16::from_be_bytes([raw[6], raw[7]]);

        Ok(Self {
            src_port,
            dst_port,
            length,
            checksum
        })
    }
}

impl TcpHeader {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() < 20 {
            return Err("Packet is too short to have a TCP Header");
        }

        let src_port = u16::from_be_bytes([raw[0], raw[1]]);
        let dst_port = u16::from_be_bytes([raw[2], raw[3]]);
        let seq_number = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let ack_number = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);
        let data_offset = (raw[12] >> 4) * 4;

        if raw.len() < data_offset as usize {
            return Err("Packet have been compromised");
        }

        let flags = u8::from_be_bytes([raw[13]]);
        let window_size = u16::from_be_bytes([raw[14], raw[15]]);
        let checksum = u16::from_be_bytes([raw[16], raw[17]]);
        let urgent_pointer = u16::from_be_bytes([raw[18], raw[19]]);

        Ok(Self {
            src_port,
            dst_port,
            seq_number,
            ack_number,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_pointer
        })
    }
}

impl EtherType {
    pub fn serialize(ether_type: EtherType) -> u16 {
        match ether_type {
            EtherType::ARP => 0x0806,
            EtherType::IPv4 => 0x0800,
            EtherType::IPv6 => 0x86DD,
            EtherType::Unknown(b) => b
        }
    }
}

impl IpProtocol {
    pub fn serialize(protocol: IpProtocol, version: u8) -> u8 {
        match protocol {
            IpProtocol::ICMP => {
                if version == 4 {
                    1 as u8
                } else {
                    58 as u8
                }
            }
            IpProtocol::TCP => 6 as u8,
            IpProtocol::UDP => 17 as u8,
            IpProtocol::Unknown(value) => value
        }
    }
}

impl ArpOperation {
    pub fn serialize(op: ArpOperation) -> u16 {
        match op {
            ArpOperation::Request => 0x0001 ,
            ArpOperation::Reply => 0x0002 ,
            ArpOperation::RRequest => 0x0003 ,
            ArpOperation::RReply => 0x0004 ,
            ArpOperation::IRequest => 0x0008 ,
            ArpOperation::IReply => 0x0009 ,
        }
    }
}