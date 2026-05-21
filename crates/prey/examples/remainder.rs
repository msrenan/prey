use std::{io::ErrorKind, net::{Ipv4Addr, SocketAddr, SocketAddrV4}};
use prey::{buffer::BufferPool, network::{Connection, RawSocket}, packet::{ArpOperation, EtherType, IpProtocol, L3, L4, Packet, TcpFlags}};

const MY_IPV4: Ipv4Addr = Ipv4Addr::new(188, 20, 57, 2);
const MY_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const BROAD_MAC: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

macro_rules! log {
    ($($arg:tt)*) => {
        println!("[PREY] :: {}", format_args!($($arg)*));
    };
}

fn main() {
    let addr = SocketAddr::V4(SocketAddrV4::new(MY_IPV4, 8080));

    let socket = RawSocket::new("tap0",
    "188.20.57.1/24".to_string(), "2006:abc::1/64".to_string()).unwrap();

    let pool = BufferPool::new(10);

    let tx = pool.acquire().unwrap();
    let rx = pool.acquire().unwrap();

    let mut conn = Connection::new(socket, addr, tx, rx).unwrap();

    let mut await_fin_confirmation = false;
    let mut remainders: Vec<String> = Vec::new();

    loop {
        match conn.receive() {
            Ok(0) => {},
            Err(e) if e.kind() == ErrorKind::WouldBlock => {},
            Err(e) => {
                log!("Error while receiving data: {}", e);
                conn.read_buffer.clear();
            },
            Ok(n) => {
                println!("\n-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n");
                log!("{} bytes received!", n);
                let packet = Packet::new(&conn.read_buffer.data());

                let (eth, l3, l4) = match packet.headers() {
                    Ok(h) => h,
                    Err(e) => {
                        log!("Error while extracting headers: {}", e);
                        conn.read_buffer.clear();
                        continue;
                    }
                };

                if eth.dst_mac != MY_MAC && eth.dst_mac != BROAD_MAC {
                    log!("Packet ignored.");
                    conn.read_buffer.clear();
                    continue;
                }

                log!("Processing packet...");

                match eth.ether_type {
                    EtherType::ARP => {
                        if let L3::ARP(arp) = l3 {
                            if arp.tgt_ip != MY_IPV4 {
                                log!("Packet ignored.");
                                conn.read_buffer.clear();
                                continue;
                            }

                            log!("ARP packet received: {}", arp);

                            if arp.op == ArpOperation::Request {
                                log!("Crafting ARP reply!");

                                let mut reply = pool.acquire().unwrap();

                                match packet.build_arp_reply(reply.as_mut_slice()) {
                                    Ok(n) => {
                                        reply.advance(n);
                                        let mut_data = reply.data_mut();

                                        mut_data[6..12].copy_from_slice(&MY_MAC);
                                        mut_data[22..28].copy_from_slice(&MY_MAC);

                                        let space = conn.write_buffer.as_mut_slice();
                                        space[..reply.data().len()].copy_from_slice(&reply.data());
                                        conn.write_buffer.advance(reply.data().len());

                                        let sent = conn.send().unwrap();
                                        log!("Sent {} bytes!", sent);
                                        conn.read_buffer.clear();
                                        continue;
                                    },
                                    Err(e) => {
                                        log!("Error crafting ARP-Reply: {}", e);
                                        conn.read_buffer.clear();
                                        conn.write_buffer.clear();
                                        continue;
                                    }
                                }
                            }
                        }
                    },
                    EtherType::Unknown(bytes) => {
                        log!("Unknown ethernet connection type: {}", bytes);
                        conn.read_buffer.clear();
                        continue;
                    },
                    EtherType::IPv6 => {
                        log!("Packet ignored");
                        conn.read_buffer.clear();
                        continue;
                    }
                    EtherType::IPv4 => {
                        if let L3::IPv4(ipv4, protocol) = l3 {
                            if ipv4.dst_ip != MY_IPV4 {
                                log!("Packet ignored.");
                                conn.read_buffer.clear();
                                continue;
                            }
                            log!("IPv4 packet received: {}", ipv4);

                            if protocol != IpProtocol::TCP {
                                log!("It's not a TCP packet. Packet ignored.");
                                conn.read_buffer.clear();
                                continue;
                            }

                            if let L4::TCP(tcp) = l4 {
                                log!("TCP packet received: {}", tcp);
                                let flags = TcpFlags::parse(tcp.flags);
                                
                                if flags == [TcpFlags::SYN] {
                                    log!("Crafting SYN-ACK.");
                                    match packet.build_tcp_syn_ack(conn.write_buffer.as_mut_slice()) {
                                        Ok(n) => {
                                            conn.write_buffer.advance(n);
                                            let sent = conn.send().unwrap();
                                            log!("Sent {} bytes!", sent);
                                            conn.read_buffer.clear();
                                            continue;
                                        },
                                        Err(e) => {
                                            log!("Error while crafting reply: {}", e);
                                            conn.read_buffer.clear();
                                            continue;
                                        }
                                    }
                                } else if flags == [TcpFlags::ACK] {
                                    log!("ACK received!");
                                    if await_fin_confirmation {
                                        log!("Connection ended.");
                                        await_fin_confirmation = false;
                                    } else {
                                        log!("Connection established.");
                                    }
                                    conn.read_buffer.clear();
                                    continue;
                                } else if flags == [TcpFlags::FIN, TcpFlags::ACK] {
                                    log!("Crafting FIN-ACK.");
                                    match packet.build_tcp_fin_ack(conn.write_buffer.as_mut_slice()) {
                                        Ok(n) => {
                                            conn.write_buffer.advance(n);
                                            let sent = conn.send().unwrap();
                                            log!("Sent {} bytes!", sent);
                                            await_fin_confirmation = true;
                                            conn.read_buffer.clear();
                                            continue;
                                        },
                                        Err(e) => {
                                            log!("Error while crafting reply: {}", e);
                                            conn.read_buffer.clear();
                                            continue;
                                        }
                                    }
                                } else if flags == [TcpFlags::PSH, TcpFlags::ACK] {
                                    log!("Request received! Start processing!");
                                    let payload = match packet.payload() {
                                        Ok(p) => p,
                                        Err(e) => {
                                            log!("Error while extracting paylaod: {}", e);
                                            conn.read_buffer.clear();
                                            continue;
                                        }
                                    };
                                    let request = String::from_utf8_lossy(&payload);
                                    if request.contains("HTTP") {
                                        log!("It's a HTTP request!");

                                        let line = request.lines().next().unwrap();
                                        let mut line_parts = line.split_whitespace();
                                        let verb = line_parts.next().unwrap();
                                        let uri = line_parts.next().unwrap();

                                        if verb != "GET" {
                                            log!("Crafting reject!");
                                            let conf_msg = format!("You can only send GET requests to this server.");
                                            match packet.build_tcp_response(conn.write_buffer.as_mut_slice(), 
                                            conf_msg.as_bytes()) {
                                                Ok(n) => {
                                                    conn.write_buffer.advance(n);
                                                    let sent = conn.send().unwrap();
                                                    log!("Sent {} bytes!", sent);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                },
                                                Err(e) => {
                                                    log!("Error while crafting confirmation: {}", e);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                }
                                            }
                                        }

                                        if uri == "/" {
                                            log!("Crafting response!");
                                            let body = format!(
                                                "<html>
                                                    <head>
                                                        <title> Remainder </title>
                                                    </head>
                                                    <body>
                                                        <h1> REMAINDERS </h1>
                                                        <ol>
                                                            {:?}    
                                                        </ol>
                                                    </body>
                                                
                                                <html/>",
                                                remainders
                                            );
                                            let response = format!(
                                                "HTTP/1.1 200 OK\r\n\
                                                Content-Type: html\r\n\
                                                Content-Length: {}\r\n\
                                                \r\n\
                                                {}",
                                                body.len(),
                                                body
                                            );

                                            match packet.build_tcp_response(conn.write_buffer.as_mut_slice(), 
                                            response.as_bytes()) {
                                                Ok(n) => {
                                                    conn.write_buffer.advance(n);
                                                    let sent = conn.send().unwrap();
                                                    log!("Sent {} bytes!", sent);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                },
                                                Err(e) => {
                                                    log!("Error while crafting reponse: {}", e);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                }
                                            }
                                        } else if uri == "/favicon.ico" {
                                            log!("Crafting /favicon reply!");
                                            let response = format!("HTTP/1.1 404 NOT FOUND\r\n\r\n");
                                            match packet.build_tcp_response(conn.write_buffer.as_mut_slice(), 
                                            response.as_bytes()) {
                                                Ok(n) => {
                                                    conn.write_buffer.advance(n);
                                                    let sent = conn.send().unwrap();
                                                    log!("Sent {} bytes!", sent);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                },
                                                Err(e) => {
                                                    log!("Error while crafting reponse: {}", e);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                }
                                            }
                                        }


                                    } else if request.contains("REMAINDER") {
                                        log!("It's a REMAINDER request!");
                                        let content = request.split_once(" ").unwrap().1.replace("\n", "");
                                        log!("Adding {} to the remainder list!", content);
                                        let tmp = format!("<li>{}</li>\n", content);
                                        remainders.push(tmp);

                                        log!("Crafting confirmation!");
                                        let conf_msg = format!("ADDED {} TO REMAINDER LIST SUCCESSFULLY!\n", content);

                                        match packet.build_tcp_response(conn.write_buffer.as_mut_slice(), 
                                        conf_msg.as_bytes()) {
                                            Ok(n) => {
                                                conn.write_buffer.advance(n);
                                                let sent = conn.send().unwrap();
                                                log!("Sent {} bytes!", sent);
                                                conn.read_buffer.clear();
                                                continue;
                                            },
                                            Err(e) => {
                                                log!("Error while crafting confirmation: {}", e);
                                                conn.read_buffer.clear();
                                                continue;
                                            }
                                        }
                                    }
                                }
                            }

                            
                            
                        }
                    }
                }


            }
        }
    }
}