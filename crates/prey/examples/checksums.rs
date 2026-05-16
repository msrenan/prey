
use std::net::Ipv4Addr;

use prey::packet::{IPv4Header, IpProtocol, calculate_checksum, calculate_checksum_v4};
fn main() {

    let generic_data: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    let result = calculate_checksum(&generic_data);

    println!("Expected: 0x663 | Received: {:04X} | Bytes: {:?}", result, result.to_be_bytes());

    let generic_data: [u8; 3] = [0xFF, 0xFE, 0x01];

    let result = calculate_checksum(&generic_data);

    println!("Expected: 0xFF00 | Received: {:04X} | Bytes: {:?}", result, result.to_be_bytes());

    let mut h = IPv4Header {
        version: 4,
        ihl: 5,
        tos: 0,
        total_len: 0x0054,
        id: 0xAABB,
        flags: 0x4000,
        ttl: 0x40,
        protocol: IpProtocol::ICMP,
        checksum: 0,
        src_ip: Ipv4Addr::new(192, 168, 1, 1),
        dst_ip: Ipv4Addr::new(192, 168, 1, 2)     
    };

    println!("Calculating ipv4 checksum for header => {}", h);

    let result = calculate_checksum_v4(&mut h);

    println!("Expected: 0x7A30 | Received: {:04X} | Bytes: {:?}", result, result.to_be_bytes())
}