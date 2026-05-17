
use std::{io, net::{Ipv4Addr, SocketAddr, SocketAddrV4}};
use prey::{buffer::BufferPool, network::{Connection, RawSocket}, packet::{ArpOperation, IpProtocol, L3, L4, Packet, TcpFlags}};

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

                println!("--------------------");
                println!("{}", packet);
                

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

                        if eth.dst_mac == BROAD_MAC || eth.dst_mac == MY_MAC {
                            println!("It's a broadcasted request.");

                            if arp.tgt_ip == MY_IP {
                                println!("It's for me!");

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
                } else if let L3::IPv4(_, protocol) = l3 {
                    if protocol == IpProtocol::ICMP {
                        println!("Its a ICMP packet!");
                        let mut response = pool.acquire().unwrap();

                        match packet.build_icmp_reply(response.as_mut_slice()) {
                            Ok(n) => {
                                println!("{} bytes written!", n);
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

                    } else if protocol == IpProtocol::TCP {
                        println!("It's a TCP packet!");
                        let (l4, _) = match packet.l4_header() {
                            Ok(data) => data,
                            Err(e) => {
                                println!("Error: {}", e);
                                conn.read_buffer.clear();
                                continue;
                            }
                        };
                        let request = match packet.payload() {
                            Ok(data) => String::from_utf8_lossy(data).into_owned(),
                            Err(e) => {
                                println!("Error getting request: {}", e);
                                conn.read_buffer.clear();
                                continue;
                            }
                        };
                        match l4 {
                            L4::TCP(tcp) => {
                                let flags = TcpFlags::parse(tcp.flags);
                                if flags == [TcpFlags::SYN] {
                                    let mut response = pool.acquire().unwrap();
                                    match packet.build_tcp_syn_ack(response.as_mut_slice()) {
                                        Ok(n) => {
                                            response.advance(n);
                                            println!("{} bytes written!", n);
                                            let space = conn.write_buffer.as_mut_slice();
                                            space[..response.data().len()].copy_from_slice(&response.data());
                                            conn.write_buffer.advance(response.data().len());

                                            println!("Sending TCP SYN-ACK!");
                                            conn.send().unwrap();
                                        },
                                        Err(e) => {
                                            println!("Error while building SYN-ACK: {}", e);
                                            conn.read_buffer.clear();
                                            continue;
                                        }
                                    }
                                } else if flags == [TcpFlags::ACK] {
                                    println!("TCP-ACK received! Connection either Established or Finished!");
                                    conn.read_buffer.clear();
                                } else if flags == [TcpFlags::PSH, TcpFlags::ACK] {
                                    println!("Packet have been acquired.");
                                    println!("{}", request);
                                    let mut response = pool.acquire().unwrap();
                                    let response_payload = format!("You have sent: {} to PREY!\n", request.replace("\n", ""));
                                    {
                                        match packet.build_tcp_response(response.as_mut_slice(), response_payload.as_bytes()) {
                                            Ok(n) => {
                                                response.advance(n);
                                                println!("{} bytes written!", n);
                                                let space = conn.write_buffer.as_mut_slice();
                                                space[..response.data().len()].copy_from_slice(&response.data());
                                                conn.write_buffer.advance(response.data().len());

                                                println!("Sending TCP ACK!");
                                                conn.send().unwrap();
                                            },
                                            Err(e) => {
                                                println!("Error while building ACK: {}", e);
                                                conn.read_buffer.clear();
                                                continue;
                                            }
                                        }
                                    }

                                    println!("Sent back ACK repsonse!");
                                } else if flags == [TcpFlags::FIN, TcpFlags::ACK] {
                                    println!("Client have nothing to send anymore.");
                                    let mut response = pool.acquire().unwrap();
                                    {
                                        match packet.build_tcp_fin_ack(response.as_mut_slice()) {
                                            Ok(n) => {
                                                response.advance(n);
                                                println!("{} bytes written!", n);
                                                let space = conn.write_buffer.as_mut_slice();
                                                space[..response.data().len()].copy_from_slice(&response.data());
                                                conn.write_buffer.advance(response.data().len());

                                                println!("Sending TCP ACK!");
                                                conn.send().unwrap();
                                            },
                                            Err(e) => {
                                                println!("Error while building ACK: {}", e);
                                                conn.read_buffer.clear();
                                                continue;
                                            }
                                        }
                                    }
                                    
                                    

                                    println!("Sent back FIN-ACK repsonse! Connection should be killed.");
                                    println!("{}", request);
                                }
                            },
                            _ => {
                                println!("This is not a TCP packet!");
                                conn.read_buffer.clear();
                                continue;
                            }
                        }
                        
                    }
                }

            println!("---------------------");
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