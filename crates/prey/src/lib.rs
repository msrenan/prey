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

pub mod buffer;
pub mod network;