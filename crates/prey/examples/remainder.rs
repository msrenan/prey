use core::fmt;
use std::{collections::HashMap, io::ErrorKind, net::{Ipv4Addr, SocketAddr, SocketAddrV4}};
use prey::{buffer::BufferPool, network::{Connection, RawSocket}, packet::{ArpOperation::{self}, EtherType, IpProtocol, L3, L4, Packet, TcpFlags}};
use prey::request::{Request, RequestMethod};

const MY_IPV4: Ipv4Addr = Ipv4Addr::new(188, 20, 57, 2);
const MY_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
const BROAD_MAC: [u8; 6] = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];

macro_rules! log {
    ($($arg:tt)*) => {
        println!("[PREY] :: {}", format_args!($($arg)*));
    };
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
struct Client {
    mac: [u8; 6],
    ip: Ipv4Addr,
    port: u16,
    http: bool
}

impl fmt::Display for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mac = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                            self.mac[0], self.mac[1], self.mac[2], self.mac[3], self.mac[4], self.mac[5]);
        write!(f,
            "Client@{} => [ *mac={} *addr={}:{} ]",
            self.ip, mac, self.ip, self.port
        )
    }
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
    let mut active_clients: HashMap<u16, Client> = HashMap::new();

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

                let (eth, l3, l4) = {
                    let packet = Packet::new(conn.read_buffer.data());
                    match packet.headers() {
                        Ok(h) => h,
                        Err(e) => {
                            log!("Error while extracting headers: {}", e);
                            conn.read_buffer.clear();
                            continue;
                        }
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
                                let packet = Packet::new(conn.read_buffer.data());
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
                                    let packet = Packet::new(conn.read_buffer.data());
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
                                        await_fin_confirmation = false;
                                        log!("Connection ended with Client@{}", ipv4.src_ip);
                                        if active_clients.contains_key(&tcp.src_port) {
                                            active_clients.remove(&tcp.src_port);
                                            log!("Client removed from active_clients list.");
                                        }
                                        
                                    } else {
                                        let new = Client {
                                            mac: eth.src_mac,
                                            ip: ipv4.src_ip,
                                            port: tcp.src_port,
                                            http: false
                                        };
                                        
                                        if !active_clients.contains_key(&new.port) {
                                            log!("Connection established: Client@{}.", new.ip);
                                            log!("Adding Client to active_clients list.");
                                            active_clients.insert(new.port, new);
                                        } else {
                                            log!("Received confirmation from Client@{}", active_clients[&new.port].ip);
                                        }
                                    }
                                    conn.read_buffer.clear();
                                    continue;
                                } else if flags == [TcpFlags::FIN, TcpFlags::ACK] {
                                    log!("Crafting FIN-ACK.");
                                    let packet = Packet::new(conn.read_buffer.data());
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
                                    let payload = {
                                        let packet = Packet::new(conn.read_buffer.data());
                                        match packet.payload() {
                                            Ok(p) => p,
                                            Err(e) => {
                                                log!("Error while extracting paylaod: {}", e);
                                                conn.read_buffer.clear();
                                                continue;
                                            }
                                        }
                                    };
                                    let request = String::from_utf8_lossy(&payload);
                                    if request.contains("HTTP") {
                                        log!("It's a HTTP request!");
                                        
                                        let r = Request::new(payload);
                                        
                                        println!("REQUEST => {}", r);

                                        let line = request.lines().next().unwrap();
                                        let mut line_parts = line.split_whitespace();
                                        let verb = line_parts.next().unwrap();
                                        let uri = line_parts.next().unwrap();

                                        if verb != "GET" {
                                            log!("Crafting reject!");
                                            let conf_msg = format!("You can only send GET requests to this server.");
                                            let packet = Packet::new(conn.read_buffer.data());
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
                                            let body_content: String = remainders.iter().map(|t| { format!("<li>{}</li>\n", t)}).collect();
                                            let body = format!(
                                                "<html>
                                                    <head>
                                                        <title> Remainder </title>
                                                    </head>
                                                    <body>
                                                        <h1> REMAINDERS </h1>
                                                        <ol>
                                                            {}    
                                                        </ol>
                                                    </body>
                                                
                                                <html/>",
                                                body_content
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
                                            let packet = Packet::new(conn.read_buffer.data());
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
                                            let packet = Packet::new(conn.read_buffer.data());
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
                                        if content == "LIST" {
                                            log!("Crafting list reply!");
                                            let list: String = remainders.iter().enumerate().map(|(n, i)| {
                                                format!("\t{}. {}\n", n, i)
                                            }).collect();
                                            let conf_msg = format!("REMAINDER LIST:\n{}", 
                                                list
                                            );
                                            let packet = Packet::new(conn.read_buffer.data());
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
                                        } else if content == "CONNECTIONS" {
                                            log!("Crafting connections reply!");
                                            let clients: String = active_clients.iter().map(|(_, v)| {
                                                format!("\t{}\n", v)
                                            }).collect();
                                            let conf_msg = format!("REMAINDER CONNs:\n{}", 
                                                clients
                                            );
                                            let packet = Packet::new(conn.read_buffer.data());
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

                                        log!("Adding {} to the remainder list!", content);
                                        remainders.push(content.to_string());

                                        log!("Crafting confirmation!");
                                        let conf_msg = format!("ADDED {} TO REMAINDER LIST SUCCESSFULLY!\n", content);
                                        {
                                            let packet = Packet::new(conn.read_buffer.data());
                                            match packet.build_tcp_response(conn.write_buffer.as_mut_slice(), 
                                            conf_msg.as_bytes()) {
                                                Ok(n) => {
                                                    conn.write_buffer.advance(n);
                                                    let sent = conn.send().unwrap();
                                                    log!("Sent {} bytes!", sent);
                                                    //conn.read_buffer.clear();
                                                    //continue;
                                                },
                                                Err(e) => {
                                                    log!("Error while crafting confirmation: {}", e);
                                                    conn.read_buffer.clear();
                                                    continue;
                                                }
                                            }
                                        }

                                        log!("Crafting response!");                                      
                                    } else {
                                        log!("Crafting error reply!");
                                        let conf_msg = format!("PLEASE ENTER A VALID COMMAND!\n");
                                        let packet = Packet::new(conn.read_buffer.data());
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