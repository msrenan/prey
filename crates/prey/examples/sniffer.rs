
use std::{io, net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4}};
use prey::{buffer::BufferPool, network::{Connection, RawSocket}, packet::{ArpOperation, IpProtocol, L3, L4, Packet, TcpFlags}};

const MY_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 50, 2);
const MY_IP_6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0002);
const MY_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const BROAD_MAC: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
fn main() {
    println!("Starting sniffer setup!");

    let pool = BufferPool::new(10);

    let dummy_adr = SocketAddr::V4(SocketAddrV4::new(MY_IP, 8080));

    let socket = RawSocket::new("tap0", "172.16.50.1/24".to_string(), "2001:db8::1/64".to_string()).unwrap();

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
                } else if let L3::IPv4(ipv4, protocol) = l3 {
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
                                    /*if ipv4.src_ip == Ipv4Addr::new(172, 16, 50, 1) {
                                        let mut response = pool.acquire().unwrap();
                                        println!("[PREY] :: BLOCKED IP DETECTED!");
                                        match packet.build_tcp_rst(response.as_mut_slice()) {
                                            Ok(n) => {
                                                response.advance(n);
                                                println!("{} bytes written!", n);
                                                let space = conn.write_buffer.as_mut_slice();
                                                space[..response.data().len()].copy_from_slice(&response.data());
                                                conn.write_buffer.advance(response.data().len());

                                                println!("Sending TCP RST!");
                                                conn.send().unwrap();
                                                conn.read_buffer.clear();
                                                continue;
                                            },
                                            Err(e) => {
                                                println!("Error while building ACK: {}", e);
                                                conn.read_buffer.clear();
                                                continue;
                                            }
                                        }
                                    } Uncomment if you want to test some IP blocking.*/
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
                                    let mut response_payload = format!("You have sent: {} to PREY!\n", request.replace("\n", ""));
                                    println!("{}", request);
                                    if request.contains("HTTP") {
                                        let body = "You have sent a HTTP request to PREY!";
                                        response_payload = format!(
                                            "HTTP/1.1 200 OK\r\n\
                                            Content-Type: text\r\n\
                                            Content-Length: {}\r\n\
                                            \r\n\
                                            {}",
                                            body.len(), body
                                        );
                                    }

                                    let mut response = pool.acquire().unwrap();
                                    
                                    {
                                        if request.contains("virus") {
                                            println!("[PREY] :: VIRUS DETECTED!");
                                            match packet.build_tcp_rst(response.as_mut_slice()) {
                                                Ok(n) => {
                                                    response.advance(n);
                                                    println!("{} bytes written!", n);
                                                    let space = conn.write_buffer.as_mut_slice();
                                                    space[..response.data().len()].copy_from_slice(&response.data());
                                                    conn.write_buffer.advance(response.data().len());

                                                    println!("Sending TCP RST!");
                                                    conn.send().unwrap();
                                                    conn.read_buffer.clear();
                                                    continue;
                                                },
                                                Err(e) => {
                                                    println!("Error while building ACK: {}", e);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                }
                                            }
                                        }

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
                        
                    } else if protocol == IpProtocol::UDP {
                        println!("It's a UDP packet!");
                        let (l4, _) = match packet.l4_header() {
                            Ok(data) => data,
                            Err(e) => {
                                println!("Error: {}", e);
                                conn.read_buffer.clear();
                                continue;
                            }
                        };

                        let payload = match packet.payload() {
                            Ok(data) => data,
                            Err(e) => {
                                println!("Error while extracting payload! [{}]", e);
                                conn.read_buffer.clear();
                                continue;
                            }
                        };

                        match l4 {
                            L4::UDP(udp) => {
                                let mut response = pool.acquire().unwrap();
                                if udp.dst_port != 8080 as u16 {
                                    println!("[PREY] :: UDP at blocked PORT");
                                    match packet.build_icmp_reject(response.as_mut_slice()) {
                                        Ok(n) => {
                                            println!("{} bytes written!", n);
                                            response.advance(n);
                                            let writable = conn.write_buffer.as_mut_slice();
                                            writable[..response.data().len()].copy_from_slice(&response.data());
                                            conn.write_buffer.advance(response.data().len());
                                            println!("Sending UDP reply!");
                                            conn.send().unwrap();
                                        },
                                        Err(e) => {
                                            println!("An error have ocurred: {}", e);
                                            conn.read_buffer.clear();
                                            continue;
                                        }
                                    };
                                }
                                let response_data = b"This is your UDP response!";

                                


                                
                            },
                            _ => {
                                println!("This is not a UDP packet.");
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