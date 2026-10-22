// SPDX-License-Identifier: MIT

//! The `netlink-packet-l2tp` crate is designed to parse and emit generic
//! netlink packets of the L2TP family. The goal of this crate is saving
//! crate users from reading the kernel netlink code.
//!
//! The L2TP generic netlink family is defined in
//! `include/uapi/linux/l2tp.h` of the Linux kernel.
//!
//! This crate only defines the packets. To talk to the kernel, use the
//! [`nl-l2tp`](https://crates.io/crates/nl-l2tp) crate, or the
//! [`l2tp`](https://crates.io/crates/l2tp) crate, a high-level facade over
//! this one that manages L2TP tunnels and sessions without exposing netlink
//! messages.
//!
//! ```no_run
//! use netlink_packet_l2tp::{
//!     L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpMessage,
//! };
//!
//! let message = L2tpMessage {
//!     cmd: L2tpCmd::TunnelCreate,
//!     attributes: vec![
//!         L2tpAttribute::ConnId(1000),
//!         L2tpAttribute::PeerConnId(2000),
//!         L2tpAttribute::ProtoVersion(3),
//!         L2tpAttribute::EncapType(L2tpEncapType::Udp),
//!     ],
//! };
//! ```

mod attribute;
mod ifname;
mod message;
#[cfg(test)]
mod test;

pub use attribute::{
    L2tpAttribute, L2tpEncapType, L2tpPwType, L2tpStatsAttribute,
};
pub use ifname::L2tpIfName;
pub use message::{L2tpCmd, L2tpMessage};
