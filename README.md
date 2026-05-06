
# PREY (Packet Routing Engine Yield)

**PREY** is a high-performance, asynchronous networking framework written in Rust.
It is designed to be a robust engine for packet routing, reverse proxies, and user-space security layers.

> This project is in early development stages!

## Vision
To provide a modular and memory-safe infrastructure for:
- Layer 4/7 Reverse Proxying
- High-throughput Load Balancing (Prey-Proxy)
- User-space Firewalls (Prey-Fire)
- Zero-Copy idea

## Modules
- ### Core
  - The main module of PREY framework, deals with memory management, streams, packets and connections.
- ### Prey-fire
  - A secondary module of PREY framework, deals with userspace firewall implementation.
- ### Prey-proxy
  - Also, a secondary module of PREY framework, deals with proxy and reverse proxy implementation.

---

# Core
The main module of PREY, its the foundation of the whole framework.
Deals with buffers' logic and management, network connection handling
packet receiving and interpretation.

### **Modules:**
- Buffer
- Network
- Packet

---

## Buffer Module
Core module that holds all buffer related code. This module defines
what is a buffer to the framework, how they behave and how they
are created.

The buffers in PREY are built on a **Buffer Pool**, this minimizes
memory access and allocation: PREY allocates memory one time, and all the
management of the allocated pool is done by itself. The pool is
sectorized in sections of 2048 bytes each, the **buffers**.

Each buffer is actually a pointer to the 2048 bytes of the pool, starting 
by an offset. The pool is a contiguous memory area, so buffers
exists "one next another". They all have starting points at 
2048 multiple. Each individual buffer uses a headroom strategy:
the first 128 buffer's bytes are skipped when writing data normally
in the buffer. It allows a more efficient header adding further
in the framework execution, so the firewall or proxy does not have to
create another buffer to insert some header before the actual data.

The whole framework is built over a **Zero-Copy** strategy.

---

## Network Module
Core module that holds all network related code. This module defines what is a connection and how to deal with it.

The connections in PREY are built to afford either connections using the **stream** (for high-level proxy and server applications) and
either for connections using **raw sockets** (for low-level firewalls applications). The way PREY deal with it is using enums to
customize de connection on the user's will. Each connection uses two buffers, one only for reading data and another only for writing data.

The **Stream** connection was built using the native rust *std::net*. This way, the language already makes everything work when the user
does not care about packets, and only care about de request (_payload_). On the other hand, to deal with **Raw Sockets** connection,
PREY uses the linux syscalls, available in `libc` C library, to be able use the **network board** and get the packets from de kernel.

---

## Packet Processing
Core module that holds all packet related code. This module define what is a packet and its headers, and how to identify,
extract and deal with it.

The packets in PREY are built using extremely memory efficient methods to not compromise the **Zero-Copy idea of the framework**.
To do so, packets use pointers and lifetimes to make sure that a Packet object only exists while the data that it represents exists too.
If the data of a packet is dropped (or even the whole buffer is dropped), the Packet object is dropped too.

This module contains routines that extract the different types of headers (IPv4, IPv6, ARP, TCP, UDP and ICMP), and all its information,
and leave some space for adding new types of headers in the future (a great way to contribute to the project, by the way)! It is responsible
for processing the packet received by the network module and forward the information gathered to other modules (such as request module) or
to the user.

Created by **Renan Machado Santos**. Built for performance.

[![Crates.io](https://img.shields.io/crates/v/prey.svg)](https://crates.io/crates/prey)
[![Documentation](https://docs.rs/prey/badge.svg)](https://docs.rs/prey)