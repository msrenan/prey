
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

## What is done so far?
- ### Buffer Module
  - Buffer Pool Structure and functionality
    - Creation and buffers sectorization
  - Buffer Structure and functionality
    - Reading, Writing and Editing data functions
- ### Network Module
  - Connection structure and functionality
    - Open a connection (Stream or RawSocket)
    - Send and receive information

- ### Packet Module
  - Packet structure
    - Packet parsing and mapping
    - Checksum math


Created by **Renan Machado Santos**. Built for performance.

[![Crates.io](https://img.shields.io/crates/v/prey.svg)](https://crates.io/crates/prey)
[![Documentation](https://docs.rs/prey/badge.svg)](https://docs.rs/prey)