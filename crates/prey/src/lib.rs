//! # Prey
//! _Packet Routing Engine Yield_
//!
//! This is the core of the whole framework
//! By now, contains buffer management and recycling.
//! > **Its still under development**
//!
//! ## Buffer Management
//! The way PREY deals with buffers is simple but smart:
//! It allocates space once, and all the remaining management is done by
//! itself. This makes PREY really efficient in terms of speed while dealing
//! with memory, since it does not need to depend on kernel and OS services during
//! its runtime, only at its start.
//!
//! It uses an efficient memory layout to prevent unnecessary space allocation,
//! using cache lines fixed on 64 bits per line.
//!
//! Buffers have a fixed size of 2048 bytes, and PREY uses the headroom strategy to allow
//! further headers adding without the need of creating another buffer. That way, the network
//! packets fit in the buffer and proxies and firewalls can easily add headers in the response.
//!
//! The whole framework is built over a **Zero-Copy** strategy.
//!
//! ## Network Handling
//! With PREY you aren't tied up with only Streams or only Raw Sockets connections. You can use the
//! framework to build your project on **both** connection styles (and even use both simultaneously)!
//! The way PREY deals with is by setting up a Connection structure that is generic, to afford streams
//! and raw sockets. It handles both styles of connection the same way, even one way begin a lot different
//! compared to the other one.
//!
//! There's no magic here. Only doing the basics well to guarantee efficiency and safety.
//!
//! For streams, we use Built in Rust std::net solution. But for analysing raw packets PREY built its own
//! way, using direct kernel **syscalls** through `libc`.
//!
//! ## Packet Processing
//! You can use PREY to built your own firewall, and to afford that, PREY has the ability to receive, understand
//! and process packets for you! This will make your work a lot easier when building a firewall. The framework
//! is able to understand the various headers a packet can have and separate the Ethernet, the IP and the Protocol headers to then, get
//! the **packet's payload** for you.
//!
//! You can either have all the headers one by one under your sight, or you can ignore then and just look for the payload.
//! Your choice! There are so many protocols to cover up, but PREY start its life as a framework covering the most important ones: TCP, UDP and ICMP.
//! There are a lot of Ethernet Connection Types too, and PREY also start its life covering the top important ones:
//! IPv4, IPv6 and ARP.
//!
//! > **But of course, as an all-purpose framework, it has a way to use unmapped protocols and Ethernet connection types. And you always can contribute, adding new
//! protocols and connection types if you feel this feature missing in the framework.**

pub mod buffer;
pub mod network;
pub mod packet;