// SPDX-License-Identifier: MIT

use std::{
    borrow::Cow,
    net::{Ipv4Addr, Ipv6Addr},
};

use netlink_packet_core::{
    DefaultNla, Emitable, Nla, NlaBuffer, Parseable, ParseableParametrized,
    emit_u16,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};
use pretty_assertions::assert_eq;

use crate::{
    L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpIfName, L2tpMessage, L2tpPwType,
    L2tpStatsAttribute,
};

/// Parse `raw` (generic netlink header followed by attributes) and check
/// that emitting the parsed message reproduces `raw` byte for byte.
fn assert_parse_and_emit(raw: &[u8], expected: &L2tpMessage) {
    let header = GenlHeader::parse(raw).unwrap();
    assert_eq!(
        &L2tpMessage::parse_with_param(&raw[4..], header).unwrap(),
        expected
    );

    let mut buffer = vec![0; expected.buffer_len() + 4];
    header.emit(&mut buffer);
    expected.emit(&mut buffer[4..]);
    assert_eq!(&buffer, &raw);
}

fn zero_stats() -> Vec<L2tpStatsAttribute> {
    vec![
        L2tpStatsAttribute::TxPackets(0),
        L2tpStatsAttribute::TxBytes(0),
        L2tpStatsAttribute::TxErrors(0),
        L2tpStatsAttribute::RxPackets(0),
        L2tpStatsAttribute::RxBytes(0),
        L2tpStatsAttribute::RxSeqDiscards(0),
        L2tpStatsAttribute::RxCookieDiscards(0),
        L2tpStatsAttribute::RxOosPackets(0),
        L2tpStatsAttribute::RxErrors(0),
        L2tpStatsAttribute::RxInvalid(0),
    ]
}

// nlmon capture of the kernel dump reply to `ip l2tp show tunnel` in a
// network namespace holding the tunnel of `ip l2tp add tunnel tunnel_id
// 1000 peer_tunnel_id 2000 encap udp local 127.0.0.1 remote 127.0.0.2
// udp_sport 1701 udp_dport 1702`. The generic netlink header is the first
// 4 bytes, the netlink header of the message is purged.
#[test]
fn test_parse_tunnel_dump_reply() {
    let raw: Vec<u8> = vec![
        0x04, 0x01, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0xd0, 0x07, 0x00, 0x00, 0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x1e, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x1a, 0x00,
        0xa5, 0x06, 0x00, 0x00, 0x06, 0x00, 0x1b, 0x00, 0xa6, 0x06, 0x00, 0x00,
        0x08, 0x00, 0x18, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x19, 0x00,
        0x7f, 0x00, 0x00, 0x02,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes: vec![
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::PeerConnId(2000),
                L2tpAttribute::Debug(0),
                L2tpAttribute::EncapType(L2tpEncapType::Udp),
                L2tpAttribute::Stats(zero_stats()),
                L2tpAttribute::UdpCsum(0),
                L2tpAttribute::UdpSport(1701),
                L2tpAttribute::UdpDport(1702),
                L2tpAttribute::IpSaddr(Ipv4Addr::new(127, 0, 0, 1)),
                L2tpAttribute::IpDaddr(Ipv4Addr::new(127, 0, 0, 2)),
            ],
        },
    );
}

// nlmon capture of the kernel dump reply to `ip l2tp show tunnel` for the
// tunnel of `ip l2tp add tunnel tunnel_id 1000 peer_tunnel_id 2000 encap udp
// local 127.0.0.1 remote 127.0.0.2 udp_sport 1701 udp_dport 1702 udp_csum
// on`.
#[test]
fn test_parse_tunnel_dump_reply_udp_csum() {
    let raw: Vec<u8> = vec![
        0x04, 0x01, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0xd0, 0x07, 0x00, 0x00, 0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x1e, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x0d, 0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x1a, 0x00,
        0xa5, 0x06, 0x00, 0x00, 0x06, 0x00, 0x1b, 0x00, 0xa6, 0x06, 0x00, 0x00,
        0x08, 0x00, 0x18, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x19, 0x00,
        0x7f, 0x00, 0x00, 0x02,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes: vec![
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::PeerConnId(2000),
                L2tpAttribute::Debug(0),
                L2tpAttribute::EncapType(L2tpEncapType::Udp),
                L2tpAttribute::Stats(zero_stats()),
                L2tpAttribute::UdpCsum(1),
                L2tpAttribute::UdpSport(1701),
                L2tpAttribute::UdpDport(1702),
                L2tpAttribute::IpSaddr(Ipv4Addr::new(127, 0, 0, 1)),
                L2tpAttribute::IpDaddr(Ipv4Addr::new(127, 0, 0, 2)),
            ],
        },
    );
}

// nlmon capture of the kernel dump reply to `ip l2tp show tunnel` for the
// UDP tunnel of `ip l2tp add tunnel tunnel_id 3000 peer_tunnel_id 4000 encap
// udp local 2001:db8::1 remote 2001:db8::2 udp_sport 1701 udp_dport 1702
// udp6_csum_tx off udp6_csum_rx off`.
#[test]
fn test_parse_tunnel_dump_reply_ipv6_udp_zero_csum() {
    let raw: Vec<u8> = vec![
        0x04, 0x01, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x09, 0x00, 0xb8, 0x0b, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0xa0, 0x0f, 0x00, 0x00, 0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x1e, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x21, 0x00, 0x04, 0x00, 0x22, 0x00, 0x06, 0x00, 0x1a, 0x00,
        0xa5, 0x06, 0x00, 0x00, 0x06, 0x00, 0x1b, 0x00, 0xa6, 0x06, 0x00, 0x00,
        0x14, 0x00, 0x1f, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x14, 0x00, 0x20, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes: vec![
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::ConnId(3000),
                L2tpAttribute::PeerConnId(4000),
                L2tpAttribute::Debug(0),
                L2tpAttribute::EncapType(L2tpEncapType::Udp),
                L2tpAttribute::Stats(zero_stats()),
                L2tpAttribute::UdpZeroCsum6Tx,
                L2tpAttribute::UdpZeroCsum6Rx,
                L2tpAttribute::UdpSport(1701),
                L2tpAttribute::UdpDport(1702),
                L2tpAttribute::Ip6Saddr(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
                )),
                L2tpAttribute::Ip6Daddr(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 2,
                )),
            ],
        },
    );
}

// nlmon capture of the kernel dump reply to `ip l2tp show tunnel` for the
// IP-encapsulated tunnel of `ip l2tp add tunnel tunnel_id 5000
// peer_tunnel_id 6000 encap ip local 2001:db8::1 remote 2001:db8::2`.
#[test]
fn test_parse_tunnel_dump_reply_ipv6_ip_encap() {
    let raw: Vec<u8> = vec![
        0x04, 0x01, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x09, 0x00, 0x88, 0x13, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0x70, 0x17, 0x00, 0x00, 0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x1e, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x14, 0x00, 0x1f, 0x00, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x14, 0x00, 0x20, 0x00,
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::TunnelGet,
            attributes: vec![
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::ConnId(5000),
                L2tpAttribute::PeerConnId(6000),
                L2tpAttribute::Debug(0),
                L2tpAttribute::EncapType(L2tpEncapType::Ip),
                L2tpAttribute::Stats(zero_stats()),
                L2tpAttribute::Ip6Saddr(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 1,
                )),
                L2tpAttribute::Ip6Daddr(Ipv6Addr::new(
                    0x2001, 0xdb8, 0, 0, 0, 0, 0, 2,
                )),
            ],
        },
    );
}

// nlmon capture of the kernel dump reply to `ip l2tp show session` for the
// session of `ip l2tp add session name l2tpeth0 tunnel_id 1000 session_id 5
// peer_session_id 6`.
#[test]
fn test_parse_session_dump_reply() {
    let raw: Vec<u8> = vec![
        0x08, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x08, 0x00, 0x0b, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0xd0, 0x07, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x6c, 0x32, 0x74, 0x70,
        0x65, 0x74, 0x68, 0x30, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x12, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x1e, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::SessionGet,
            attributes: vec![
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::SessionId(5),
                L2tpAttribute::PeerConnId(2000),
                L2tpAttribute::PeerSessionId(6),
                L2tpAttribute::Debug(0),
                L2tpAttribute::PwType(L2tpPwType::Eth),
                L2tpAttribute::if_name("l2tpeth0").unwrap(),
                L2tpAttribute::RecvSeq(0),
                L2tpAttribute::SendSeq(0),
                L2tpAttribute::LnsMode(0),
                L2tpAttribute::Stats(zero_stats()),
            ],
        },
    );
}

// nlmon capture of the kernel dump reply to `ip l2tp show session` for the
// session of `ip l2tp add session name l2tpeth0 tunnel_id 1000 session_id 5
// peer_session_id 6 cookie 01020304 peer_cookie 0102030405060708 seq both`.
#[test]
fn test_parse_session_dump_reply_cookies() {
    let raw: Vec<u8> = vec![
        0x08, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x08, 0x00, 0x0b, 0x00, 0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0xd0, 0x07, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x6c, 0x32, 0x74, 0x70,
        0x65, 0x74, 0x68, 0x30, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0f, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x05, 0x00, 0x12, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x13, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x14, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x1e, 0x00, 0x0c, 0x00, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x02, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x03, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x05, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x06, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0a, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x07, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x08, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00, 0x0b, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::SessionGet,
            attributes: vec![
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::SessionId(5),
                L2tpAttribute::PeerConnId(2000),
                L2tpAttribute::PeerSessionId(6),
                L2tpAttribute::Debug(0),
                L2tpAttribute::PwType(L2tpPwType::Eth),
                L2tpAttribute::if_name("l2tpeth0").unwrap(),
                L2tpAttribute::Cookie(vec![1, 2, 3, 4]),
                L2tpAttribute::PeerCookie(vec![1, 2, 3, 4, 5, 6, 7, 8]),
                L2tpAttribute::RecvSeq(1),
                L2tpAttribute::SendSeq(1),
                L2tpAttribute::LnsMode(0),
                L2tpAttribute::Stats(zero_stats()),
            ],
        },
    );
}

#[test]
fn test_cookie_constructors_validate_length() {
    assert!(L2tpAttribute::cookie(vec![]).is_ok());
    assert!(L2tpAttribute::cookie(vec![0; 4]).is_ok());
    assert!(L2tpAttribute::cookie(vec![0; 8]).is_ok());
    assert!(L2tpAttribute::peer_cookie(vec![]).is_ok());
    assert!(L2tpAttribute::peer_cookie(vec![0; 4]).is_ok());
    assert!(L2tpAttribute::peer_cookie(vec![0; 8]).is_ok());

    for len in [1, 2, 3, 5, 6, 7, 9] {
        assert!(L2tpAttribute::cookie(vec![0; len]).is_err());
        assert!(L2tpAttribute::peer_cookie(vec![0; len]).is_err());
    }
}

#[test]
fn test_parse_cookie_validates_length() {
    for len in [0usize, 4, 8] {
        for kind in [15u16, 16] {
            let raw = emit_nla(kind, &vec![0; len]);
            let nla = NlaBuffer::new_checked(&raw).unwrap();
            assert!(L2tpAttribute::parse(&nla).is_ok());
        }
    }

    for len in [1usize, 2, 3, 5, 6, 7, 9] {
        for kind in [15u16, 16] {
            let raw = emit_nla(kind, &vec![0; len]);
            let nla = NlaBuffer::new_checked(&raw).unwrap();
            assert!(L2tpAttribute::parse(&nla).is_err());
        }
    }
}

// nlmon capture of the kernel dump reply to `ip l2tp show session` for the
// session of `ip l2tp add session name l2tpeth6 tunnel_id 3000 session_id 7
// peer_session_id 8` on an IPv6 tunnel.
#[test]
fn test_parse_session_dump_reply_ipv6() {
    let raw: Vec<u8> = vec![
        0x08, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0xb8, 0x0b, 0x00, 0x00,
        0x08, 0x00, 0x0b, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0a, 0x00,
        0xa0, 0x0f, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x08, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x01, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x08, 0x00, 0x6c, 0x32, 0x74, 0x70,
        0x65, 0x74, 0x68, 0x36, 0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x12, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x05, 0x00, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7c, 0x00, 0x1e, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::SessionGet,
            attributes: vec![
                L2tpAttribute::ConnId(3000),
                L2tpAttribute::SessionId(7),
                L2tpAttribute::PeerConnId(4000),
                L2tpAttribute::PeerSessionId(8),
                L2tpAttribute::Debug(0),
                L2tpAttribute::PwType(L2tpPwType::Eth),
                L2tpAttribute::if_name("l2tpeth6").unwrap(),
                L2tpAttribute::RecvSeq(0),
                L2tpAttribute::SendSeq(0),
                L2tpAttribute::LnsMode(0),
                L2tpAttribute::Stats(zero_stats()),
            ],
        },
    );
}

#[test]
fn test_ifname_constructor_validate_length() {
    assert!(L2tpAttribute::if_name("x").is_ok());
    assert!(L2tpAttribute::if_name("x".repeat(15)).is_ok());
    assert!(L2tpAttribute::if_name("x".repeat(16)).is_err());
}

#[test]
fn test_parse_ifname_validates_length() {
    let mut value = "x".repeat(15).into_bytes();
    value.push(0);
    let raw = emit_nla(8, &value);
    let nla = NlaBuffer::new_checked(&raw).unwrap();
    assert!(L2tpAttribute::parse(&nla).is_ok());

    let mut value = "x".repeat(16).into_bytes();
    value.push(0);
    let raw = emit_nla(8, &value);
    let nla = NlaBuffer::new_checked(&raw).unwrap();
    assert!(L2tpAttribute::parse(&nla).is_err());
}

// nlmon capture of the request sent by `ip l2tp add tunnel tunnel_id 1000
// peer_tunnel_id 2000 encap udp local 127.0.0.1 remote 127.0.0.2 udp_sport
// 1701 udp_dport 1702`.
#[test]
fn test_parse_tunnel_create_request() {
    let raw: Vec<u8> = vec![
        0x01, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0xd0, 0x07, 0x00, 0x00, 0x05, 0x00, 0x07, 0x00,
        0x03, 0x00, 0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x08, 0x00, 0x18, 0x00, 0x7f, 0x00, 0x00, 0x01, 0x08, 0x00, 0x19, 0x00,
        0x7f, 0x00, 0x00, 0x02, 0x06, 0x00, 0x1a, 0x00, 0xa5, 0x06, 0x00, 0x00,
        0x06, 0x00, 0x1b, 0x00, 0xa6, 0x06, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::TunnelCreate,
            attributes: vec![
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::PeerConnId(2000),
                L2tpAttribute::ProtoVersion(3),
                L2tpAttribute::EncapType(L2tpEncapType::Udp),
                L2tpAttribute::IpSaddr(Ipv4Addr::new(127, 0, 0, 1)),
                L2tpAttribute::IpDaddr(Ipv4Addr::new(127, 0, 0, 2)),
                L2tpAttribute::UdpSport(1701),
                L2tpAttribute::UdpDport(1702),
            ],
        },
    );
}

// nlmon capture of the request sent by `ip l2tp add session name l2tpeth0
// tunnel_id 1000 session_id 5 peer_session_id 6`.
#[test]
fn test_parse_session_create_request() {
    let raw: Vec<u8> = vec![
        0x05, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x08, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0b, 0x00,
        0x05, 0x00, 0x00, 0x00, 0x08, 0x00, 0x0c, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x01, 0x00, 0x05, 0x00, 0x00, 0x00, 0x05, 0x00, 0x05, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x06, 0x00, 0x04, 0x00, 0x00, 0x00,
        0x0d, 0x00, 0x08, 0x00, 0x6c, 0x32, 0x74, 0x70, 0x65, 0x74, 0x68, 0x30,
        0x00, 0x00, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::SessionCreate,
            attributes: vec![
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::PeerConnId(0),
                L2tpAttribute::SessionId(5),
                L2tpAttribute::PeerSessionId(6),
                L2tpAttribute::PwType(L2tpPwType::Eth),
                L2tpAttribute::L2SpecType(1),
                L2tpAttribute::L2SpecLen(4),
                L2tpAttribute::if_name("l2tpeth0").unwrap(),
            ],
        },
    );
}

// L2TP_ATTR_DATA_SEQ is unused by the kernel and is therefore never
// present in an nlmon capture. The kernel netlink policy defines it as
// NLA_U8 (net/l2tp/l2tp_netlink.c), so the attribute is built by hand.
#[test]
fn test_parse_data_seq_u8() {
    let raw: Vec<u8> = vec![
        0x07, 0x01, 0x00, 0x00, // genl header: session_modify, version 1
        0x05, 0x00, 0x04, 0x00, 0x02, 0x00, 0x00, 0x00, // DATA_SEQ=2
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::SessionModify,
            attributes: vec![L2tpAttribute::DataSeq(2)],
        },
    );
}

#[test]
fn test_parse_data_seq_rejects_u16_payload() {
    let raw: Vec<u8> = vec![
        0x07, 0x01, 0x00, 0x00, // genl header: session_modify, version 1
        0x06, 0x00, 0x04, 0x00, 0x01, 0x02, 0x00, 0x00, // 2-byte payload
    ];

    let header = GenlHeader::parse(&raw).unwrap();
    assert!(L2tpMessage::parse_with_param(&raw[4..], header).is_err());
}

#[test]
fn test_parse_tunnel_dump_request() {
    let raw: Vec<u8> = vec![0x04, 0x01, 0x00, 0x00];

    assert_parse_and_emit(&raw, &L2tpMessage::new(L2tpCmd::TunnelGet));
}

#[test]
fn test_parse_session_dump_request() {
    let raw: Vec<u8> = vec![0x08, 0x01, 0x00, 0x00];

    assert_parse_and_emit(&raw, &L2tpMessage::new(L2tpCmd::SessionGet));
}

#[test]
fn test_parse_session_delete_request() {
    let raw: Vec<u8> = vec![
        0x06, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00,
        0x08, 0x00, 0x0b, 0x00, 0x05, 0x00, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::SessionDelete,
            attributes: vec![
                L2tpAttribute::ConnId(1000),
                L2tpAttribute::SessionId(5),
            ],
        },
    );
}

#[test]
fn test_parse_tunnel_delete_request() {
    let raw: Vec<u8> = vec![
        0x02, 0x01, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00, 0xe8, 0x03, 0x00, 0x00,
    ];

    assert_parse_and_emit(
        &raw,
        &L2tpMessage {
            cmd: L2tpCmd::TunnelDelete,
            attributes: vec![L2tpAttribute::ConnId(1000)],
        },
    );
}

#[test]
fn test_family_name() {
    assert_eq!(L2tpMessage::family_name(), "l2tp");
}

#[test]
fn test_ifname_rejects_nul_in_constructor() {
    for name in ["\0", "eth0\0suffix", "eth0\0"] {
        assert!(L2tpAttribute::if_name(name).is_err());
    }
}

#[test]
fn test_parse_ifname_reads_a_c_string() {
    // Keep accepting the unterminated strings supported in 0.3.0, and
    // count UTF-8 names in bytes rather than characters.
    for name in ["eth0", "éééééééx"] {
        for terminated in [false, true] {
            let mut payload = name.as_bytes().to_vec();
            if terminated {
                payload.push(0);
            }
            let raw = emit_nla(8, &payload);
            assert_eq!(
                L2tpAttribute::parse(&NlaBuffer::new(&raw)).unwrap(),
                L2tpAttribute::if_name(name).unwrap()
            );
        }
    }
    assert!(L2tpAttribute::if_name("é".repeat(8)).is_err());

    // Like the kernel, ignore everything after the first NUL.
    for (payload, name) in [
        (&b"eth0\0\0\0"[..], "eth0"),
        (&b"eth0\0suffix\0"[..], "eth0"),
        (&b"l2tpeth%d\0\0"[..], "l2tpeth%d"),
        (&b"xxxxxxxxxxxxxxx\0\0\0\0\0"[..], "xxxxxxxxxxxxxxx"),
    ] {
        let raw = emit_nla(8, payload);
        assert_eq!(
            L2tpAttribute::parse(&NlaBuffer::new(&raw)).unwrap(),
            L2tpAttribute::if_name(name).unwrap()
        );
    }
    for payload in [&b"\0\0"[..], b"\0suffix\0"] {
        let raw = emit_nla(8, payload);
        assert!(L2tpAttribute::parse(&NlaBuffer::new(&raw)).is_err());
    }
}

#[test]
fn test_ifname_follows_kernel_dev_valid_name() {
    for name in ["eth0", "l2tpeth%d", "a.b", "...", "é", "-_+@"] {
        assert!(L2tpAttribute::if_name(name).is_ok(), "{name:?}");
    }
    for name in [
        "", ".", "..", "a/b", "a:b", "a b", "a\tb", "a\nb", "a\x0bb", "a\x0cb",
        "a\rb", "a\u{a0}b", "à",
    ] {
        assert!(L2tpAttribute::if_name(name).is_err(), "{name:?}");
        let raw = emit_nla(8, name.as_bytes());
        assert!(
            L2tpAttribute::parse(&NlaBuffer::new(&raw)).is_err(),
            "{name:?}"
        );
    }
}

#[test]
fn test_ifname_supports_non_utf8_names() {
    let name = L2tpIfName::new(b"eth\xff").unwrap();
    assert_eq!(name.as_bytes(), b"eth\xff");
    assert!(name.to_str().is_err());
    assert_eq!(name.to_string(), "eth\u{fffd}");
    assert_eq!(format!("{name:?}"), r#"L2tpIfName("eth\xff")"#);

    let attribute = L2tpAttribute::IfName(name);
    let mut raw = vec![0; attribute.buffer_len()];
    attribute.emit(&mut raw);
    assert_eq!(raw, emit_nla(8, b"eth\xff\0"));
    assert_eq!(
        L2tpAttribute::parse(&NlaBuffer::new(&raw)).unwrap(),
        attribute
    );
}

#[test]
fn test_ifname_conversions() {
    let eth0 = L2tpIfName::new("eth0").unwrap();
    assert_eq!(eth0.as_bytes(), b"eth0");
    assert_eq!(eth0.to_str().unwrap(), "eth0");
    assert_eq!(eth0.as_array(), b"eth0\0\0\0\0\0\0\0\0\0\0\0\0");
    assert_eq!(<[u8; 16]>::from(eth0), *b"eth0\0\0\0\0\0\0\0\0\0\0\0\0");

    let string = "eth0".to_string();
    assert_eq!(L2tpIfName::try_from("eth0").unwrap(), eth0);
    assert_eq!(L2tpIfName::try_from(&string).unwrap(), eth0);
    assert_eq!(L2tpIfName::try_from(string.clone()).unwrap(), eth0);
    assert_eq!(L2tpIfName::try_from(&b"eth0"[..]).unwrap(), eth0);
    assert_eq!(L2tpIfName::try_from(b"eth0".to_vec()).unwrap(), eth0);
    assert_eq!("eth0".parse::<L2tpIfName>().unwrap(), eth0);
    assert_eq!(
        L2tpIfName::from_str_ref(Cow::Borrowed("eth0")).unwrap(),
        eth0
    );
    assert_eq!(
        L2tpIfName::from_str_ref(Box::<str>::from("eth0")).unwrap(),
        eth0
    );
    assert_eq!(L2tpIfName::from_string(string).unwrap(), eth0);
    assert_eq!(L2tpIfName::from_string('x').unwrap().as_bytes(), b"x");

    // Bytes after the first NUL are dropped, so equal names compare equal.
    let mut buffer = *b"eth0\0garbage\0\0\0\0";
    assert_eq!(L2tpIfName::try_from(buffer).unwrap(), eth0);
    buffer = [b'x'; 16];
    assert!(L2tpIfName::try_from(buffer).is_err());
    buffer[15] = 0;
    assert_eq!(L2tpIfName::try_from(buffer).unwrap().as_bytes(), [b'x'; 15]);
}

#[test]
fn test_invalid_public_variants_are_rejected_before_message_writes() {
    let invalid = vec![
        L2tpAttribute::Cookie(vec![0; 1]),
        L2tpAttribute::PeerCookie(vec![0; 9]),
        L2tpAttribute::Cookie(vec![0; 65536]),
        L2tpAttribute::Other(DefaultNla::new(100, vec![0; 65532])),
        L2tpAttribute::Stats(vec![L2tpStatsAttribute::Other(DefaultNla::new(
            100,
            vec![0; 65532],
        ))]),
        L2tpAttribute::Stats(vec![L2tpStatsAttribute::TxBytes(0); 5461]),
        // Raw variants cannot bypass validation of known types.
        L2tpAttribute::Other(DefaultNla::new(15, vec![0; 1])),
        L2tpAttribute::Other(DefaultNla::new(8, b"a:b\0".to_vec())),
        L2tpAttribute::Stats(vec![L2tpStatsAttribute::Other(DefaultNla::new(
            1,
            vec![0; 1],
        ))]),
        L2tpAttribute::Other(DefaultNla::new(30, emit_nla(1, &[0]))),
    ];
    for attribute in invalid {
        let message = L2tpMessage {
            cmd: L2tpCmd::SessionCreate,
            attributes: vec![L2tpAttribute::ConnId(1), attribute],
        };
        let mut buffer = vec![0xa5; 70000];
        let result =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                message.emit(&mut buffer)
            }));
        assert!(result.is_err(), "accepted invalid message: {message:?}");
        assert!(buffer.iter().all(|byte| *byte == 0xa5));
    }
}

#[test]
fn test_direct_attribute_emission_rejects_invalid_variants() {
    for attribute in [
        L2tpAttribute::Cookie(vec![0; 3]),
        L2tpAttribute::PeerCookie(vec![0; 5]),
        L2tpAttribute::Other(DefaultNla::new(15, vec![0; 3])),
    ] {
        let result = std::panic::catch_unwind(|| {
            let mut buffer = vec![0; attribute.buffer_len()];
            attribute.emit(&mut buffer);
        });
        assert!(result.is_err());
    }
    let stat = L2tpStatsAttribute::Other(DefaultNla::new(9, vec![0]));
    assert!(
        std::panic::catch_unwind(|| {
            stat.emit(&mut vec![0; stat.buffer_len()]);
        })
        .is_err()
    );
}

#[test]
fn test_attribute_length_limits_include_header_but_not_padding() {
    for len in [65530, 65531] {
        let attribute =
            L2tpAttribute::Other(DefaultNla::new(100, vec![42; len]));
        let mut raw = vec![0; attribute.buffer_len()];
        attribute.emit(&mut raw);
        assert_eq!(raw.len(), 65536);
        assert_eq!(
            L2tpAttribute::parse(&NlaBuffer::new_checked(&raw).unwrap())
                .unwrap(),
            attribute
        );
        let stat =
            L2tpStatsAttribute::Other(DefaultNla::new(100, vec![42; len]));
        stat.emit(&mut raw);
        assert_eq!(
            L2tpStatsAttribute::parse(&NlaBuffer::new(&raw)).unwrap(),
            stat
        );
    }
    for len in [65532, 65535, 65536] {
        let attribute =
            L2tpAttribute::Other(DefaultNla::new(100, vec![0; len]));
        assert!(std::panic::catch_unwind(|| attribute.value_len()).is_err());
        let stat =
            L2tpStatsAttribute::Other(DefaultNla::new(100, vec![0; len]));
        assert!(std::panic::catch_unwind(|| stat.value_len()).is_err());
    }
}

#[test]
fn test_stats_length_limit_includes_aligned_children() {
    for len in [65523, 65524, 65525, 65528] {
        let attribute = L2tpAttribute::Stats(vec![L2tpStatsAttribute::Other(
            DefaultNla::new(100, vec![42; len]),
        )]);
        if len <= 65524 {
            let mut raw = vec![0; attribute.buffer_len()];
            attribute.emit(&mut raw);
            assert_eq!(raw.len(), 65532);
            assert_eq!(
                L2tpAttribute::parse(&NlaBuffer::new(&raw)).unwrap(),
                attribute
            );
        } else {
            assert!(
                std::panic::catch_unwind(|| attribute.value_len()).is_err()
            );
        }
    }
}

#[test]
fn test_parsers_reject_unchecked_malformed_nla_headers_without_panicking() {
    for raw in [
        vec![],
        vec![0],
        vec![0; 3],
        vec![3, 0, 1, 0],
        vec![8, 0, 1, 0],
    ] {
        let nla = NlaBuffer::new(&raw);
        assert!(L2tpAttribute::parse(&nla).is_err());
        assert!(L2tpStatsAttribute::parse(&nla).is_err());
    }
}

#[test]
fn test_flags_and_padding_reject_nonempty_payloads() {
    for kind in [33, 34, 35] {
        let raw = emit_nla(kind, &[0]);
        assert!(L2tpAttribute::parse(&NlaBuffer::new(&raw)).is_err());
        let raw = emit_nla(kind, &[]);
        assert!(L2tpAttribute::parse(&NlaBuffer::new(&raw)).is_ok());
    }
    let raw = emit_nla(9, &[0]);
    assert!(L2tpStatsAttribute::parse(&NlaBuffer::new(&raw)).is_err());
    let raw = emit_nla(9, &[]);
    assert_eq!(
        L2tpStatsAttribute::parse(&NlaBuffer::new(&raw)).unwrap(),
        L2tpStatsAttribute::Pad
    );
}

#[test]
fn test_valid_raw_known_attributes_and_future_values_still_emit() {
    for (kind, payload) in [
        (15, vec![1; 4]),
        (8, b"eth0\0".to_vec()),
        (18, vec![2]),
        (30, emit_nla(100, &[1, 2, 3])),
        (100, vec![1, 2, 3]),
    ] {
        let attribute =
            L2tpAttribute::Other(DefaultNla::new(kind, payload.clone()));
        let mut raw = vec![0; attribute.buffer_len()];
        attribute.emit(&mut raw);
        assert_eq!(raw, emit_nla(kind, &payload));
    }
}

#[test]
fn test_short_message_output_buffer_is_rejected_before_writing() {
    let message = L2tpMessage {
        cmd: L2tpCmd::TunnelCreate,
        attributes: vec![
            L2tpAttribute::ConnId(1),
            L2tpAttribute::PeerConnId(2),
        ],
    };
    let mut buffer = vec![0xa5; message.buffer_len() - 1];
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            message.emit(&mut buffer);
        }))
        .is_err()
    );
    assert!(buffer.iter().all(|byte| *byte == 0xa5));
}

fn emit_nla(kind: u16, value: &[u8]) -> Vec<u8> {
    let len = 4 + value.len();
    let aligned_len = (len + 3) & !3;
    let mut raw = vec![0u8; aligned_len];
    emit_u16(&mut raw[0..2], len as u16).unwrap();
    emit_u16(&mut raw[2..4], kind).unwrap();
    raw[4..(4 + value.len())].copy_from_slice(value);
    raw
}
