
use std::{io, net::{Ipv4Addr, SocketAddr, SocketAddrV4}};

use libc::name_t;
use prey::{buffer::BufferPool, network::{Connection, RawSocket}, packet::{ArpOperation, IpProtocol, L3, Packet}};

const MY_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 50, 2);
const MY_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const BROAD_MAC: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
fn main() {

    println!("Starting sniffer setup!");

    let pool = BufferPool::new(10);

    let dummy_adr = SocketAddr::V4(SocketAddrV4::new(MY_IP, 8080));

    let socket = RawSocket::new("tap0", "172.16.50.1/24".to_string()).unwrap();

    let tx = pool.acquire().unwrap();
    let rx = pool.acquire().unwrap();

    let mut conn = Connection::new(socket, dummy_adr, tx, rx).unwrap();

    loop {
        match conn.receive() {
            Ok(0) => {},
            Ok(n) => {
                println!("{} bytes received!", n);


                let packet = Packet::new(conn.read_buffer.data());

                let (l3, _) = match packet.l3_header() {
                    Ok(data) => data,
                    Err(e) => {
                        println!("Error -> {}", e);
                        conn.read_buffer.clear();
                        continue;
                    }
                };
                let (eth, _) = packet.ethernet_header().unwrap();
                if let L3::ARP(arp) = l3 {
                    if arp.op == ArpOperation::Request {
                        println!("Its an arp request!");
                        println!("{}", packet);

                        if eth.dst_mac == BROAD_MAC || eth.dst_mac == MY_MAC {
                            println!("It's a broadcasted request.");

                            if arp.tgt_ip == MY_IP {
                                println!("It's for ME!");

                                let mut response = pool.acquire().unwrap();
                                let reply = packet.build_arp_reply(response.as_mut_slice());

                                match reply {
                                    Ok(n) => {
                                        response.advance(n);
                                    },
                                    Err(e) => {
                                        println!("Erro: {}", e);
                                        conn.read_buffer.clear();
                                        continue;
                                    }
                                }

                                let edit = response.data_mut();

                                edit[6..12].copy_from_slice(&MY_MAC);
                                edit[22..28].copy_from_slice(&MY_MAC);

                                let wb = conn.write_buffer.as_mut_slice();
                                wb[..edit.len()].copy_from_slice(&edit);
                                conn.write_buffer.advance(edit.len() as usize);

                                println!("Sending ARP Reply!");
                                conn.send().unwrap();
                            }
                        }

                    }
                } else if let L3::IPv4(ipv4, protocol) = l3 {
                    if protocol == IpProtocol::ICMP {
                        println!("Its a ICMP packet!");
                        //println!("{}", packet);
                        println!("{:02X?}", packet.raw);

                        let mut response = pool.acquire().unwrap();

                        match packet.build_icmp_reply(response.as_mut_slice()) {
                            Ok(n) => {
                                println!("Works! ({} bytes written!)", n);
                                response.advance(n);
                                let writable = conn.write_buffer.as_mut_slice();
                                writable[..response.data().len()].copy_from_slice(&response.data());
                                conn.write_buffer.advance(response.data().len());
                                println!("Sending ping reply!");
                                conn.send().unwrap();
                            },
                            Err(e) => {
                                println!("An error have ocurred: {}", e);
                                conn.read_buffer.clear();
                                continue;
                            }
                        };

                    }
                }


            },
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                //Does nothing.
            },
            Err(e) => {
                println!("Error: {}", e);
            }
        }
        conn.read_buffer.clear();
    }

}