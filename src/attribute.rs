// SPDX-License-Identifier: MIT

use std::net::{Ipv4Addr, Ipv6Addr};

use netlink_packet_core::{
    DecodeError, DefaultNla, Emitable, ErrorContext, Nla, NlaBuffer,
    NlasIterator, Parseable, emit_i32, emit_u16, emit_u32, emit_u64, parse_i32,
    parse_string, parse_u8, parse_u16, parse_u32, parse_u64,
};

const L2TP_ATTR_PW_TYPE: u16 = 1;
const L2TP_ATTR_ENCAP_TYPE: u16 = 2;
const L2TP_ATTR_OFFSET: u16 = 3;
const L2TP_ATTR_DATA_SEQ: u16 = 4;
const L2TP_ATTR_L2SPEC_TYPE: u16 = 5;
const L2TP_ATTR_L2SPEC_LEN: u16 = 6;
const L2TP_ATTR_PROTO_VERSION: u16 = 7;
const L2TP_ATTR_IFNAME: u16 = 8;
const L2TP_ATTR_CONN_ID: u16 = 9;
const L2TP_ATTR_PEER_CONN_ID: u16 = 10;
const L2TP_ATTR_SESSION_ID: u16 = 11;
const L2TP_ATTR_PEER_SESSION_ID: u16 = 12;
const L2TP_ATTR_UDP_CSUM: u16 = 13;
const L2TP_ATTR_VLAN_ID: u16 = 14;
const L2TP_ATTR_COOKIE: u16 = 15;
const L2TP_ATTR_PEER_COOKIE: u16 = 16;
const L2TP_ATTR_DEBUG: u16 = 17;
const L2TP_ATTR_RECV_SEQ: u16 = 18;
const L2TP_ATTR_SEND_SEQ: u16 = 19;
const L2TP_ATTR_LNS_MODE: u16 = 20;
const L2TP_ATTR_USING_IPSEC: u16 = 21;
const L2TP_ATTR_RECV_TIMEOUT: u16 = 22;
const L2TP_ATTR_FD: u16 = 23;
const L2TP_ATTR_IP_SADDR: u16 = 24;
const L2TP_ATTR_IP_DADDR: u16 = 25;
const L2TP_ATTR_UDP_SPORT: u16 = 26;
const L2TP_ATTR_UDP_DPORT: u16 = 27;
const L2TP_ATTR_MTU: u16 = 28;
const L2TP_ATTR_MRU: u16 = 29;
const L2TP_ATTR_STATS: u16 = 30;
const L2TP_ATTR_IP6_SADDR: u16 = 31;
const L2TP_ATTR_IP6_DADDR: u16 = 32;
const L2TP_ATTR_UDP_ZERO_CSUM6_TX: u16 = 33;
const L2TP_ATTR_UDP_ZERO_CSUM6_RX: u16 = 34;
const L2TP_ATTR_PAD: u16 = 35;

const L2TP_ATTR_TX_PACKETS: u16 = 1;
const L2TP_ATTR_TX_BYTES: u16 = 2;
const L2TP_ATTR_TX_ERRORS: u16 = 3;
const L2TP_ATTR_RX_PACKETS: u16 = 4;
const L2TP_ATTR_RX_BYTES: u16 = 5;
const L2TP_ATTR_RX_SEQ_DISCARDS: u16 = 6;
const L2TP_ATTR_RX_OOS_PACKETS: u16 = 7;
const L2TP_ATTR_RX_ERRORS: u16 = 8;
const L2TP_ATTR_STATS_PAD: u16 = 9;
const L2TP_ATTR_RX_COOKIE_DISCARDS: u16 = 10;
const L2TP_ATTR_RX_INVALID: u16 = 11;

/// A cookie is either absent or 4 or 8 bytes long, see
/// `L2TP_ATTR_COOKIE` of the kernel.
const L2TP_COOKIE_MAX_LEN: usize = 8;
/// Maximum length of an interface name, `IFNAMSIZ - 1` of the kernel.
const L2TP_IFNAME_MAX_LEN: usize = 15;

/// L2TP control connection over UDP, `L2TP_ENCAPTYPE_UDP` of the kernel.
/// Exposed through [L2tpEncapType::Udp], the raw value stays private.
const L2TP_ENCAPTYPE_UDP: u16 = 0;
/// L2TP control connection over IP (no UDP), `L2TP_ENCAPTYPE_IP` of the
/// kernel. Exposed through [L2tpEncapType::Ip], the raw value stays
/// private.
const L2TP_ENCAPTYPE_IP: u16 = 1;

const L2TP_PWTYPE_NONE: u16 = 0x0000;
const L2TP_PWTYPE_ETH_VLAN: u16 = 0x0004;
const L2TP_PWTYPE_ETH: u16 = 0x0005;
const L2TP_PWTYPE_PPP: u16 = 0x0007;
const L2TP_PWTYPE_PPP_AC: u16 = 0x0008;
const L2TP_PWTYPE_IP: u16 = 0x000b;

/// Pseudowire type of a session, see `L2TP_ATTR_PW_TYPE` and
/// `enum l2tp_pwtype` of the kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpPwType {
    None,
    /// Ethernet pseudowire with VLAN.
    EthVlan,
    /// Ethernet pseudowire.
    Eth,
    Ppp,
    PppAc,
    Ip,
    Other(u16),
}

impl From<u16> for L2tpPwType {
    fn from(value: u16) -> Self {
        match value {
            L2TP_PWTYPE_NONE => Self::None,
            L2TP_PWTYPE_ETH_VLAN => Self::EthVlan,
            L2TP_PWTYPE_ETH => Self::Eth,
            L2TP_PWTYPE_PPP => Self::Ppp,
            L2TP_PWTYPE_PPP_AC => Self::PppAc,
            L2TP_PWTYPE_IP => Self::Ip,
            value => Self::Other(value),
        }
    }
}

impl From<L2tpPwType> for u16 {
    fn from(value: L2tpPwType) -> Self {
        match value {
            L2tpPwType::None => L2TP_PWTYPE_NONE,
            L2tpPwType::EthVlan => L2TP_PWTYPE_ETH_VLAN,
            L2tpPwType::Eth => L2TP_PWTYPE_ETH,
            L2tpPwType::Ppp => L2TP_PWTYPE_PPP,
            L2tpPwType::PppAc => L2TP_PWTYPE_PPP_AC,
            L2tpPwType::Ip => L2TP_PWTYPE_IP,
            L2tpPwType::Other(value) => value,
        }
    }
}

/// Encapsulation type of a tunnel, see `L2TP_ATTR_ENCAP_TYPE` of the
/// kernel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpEncapType {
    /// L2TP control connection over UDP.
    Udp,
    /// L2TP control connection over IP without UDP.
    Ip,
    Other(u16),
}

impl From<u16> for L2tpEncapType {
    fn from(value: u16) -> Self {
        match value {
            L2TP_ENCAPTYPE_UDP => Self::Udp,
            L2TP_ENCAPTYPE_IP => Self::Ip,
            value => Self::Other(value),
        }
    }
}

impl From<L2tpEncapType> for u16 {
    fn from(value: L2tpEncapType) -> Self {
        match value {
            L2tpEncapType::Udp => L2TP_ENCAPTYPE_UDP,
            L2tpEncapType::Ip => L2TP_ENCAPTYPE_IP,
            L2tpEncapType::Other(value) => value,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpAttribute {
    PwType(L2tpPwType),
    EncapType(L2tpEncapType),
    Offset(u16),
    DataSeq(u8),
    L2SpecType(u8),
    L2SpecLen(u8),
    ProtoVersion(u8),
    IfName(String),
    ConnId(u32),
    PeerConnId(u32),
    SessionId(u32),
    PeerSessionId(u32),
    UdpCsum(u8),
    VlanId(u16),
    Cookie(Vec<u8>),
    PeerCookie(Vec<u8>),
    Debug(u32),
    RecvSeq(u8),
    SendSeq(u8),
    LnsMode(u8),
    UsingIpsec(u8),
    RecvTimeout(u64),
    Fd(i32),
    IpSaddr(Ipv4Addr),
    IpDaddr(Ipv4Addr),
    UdpSport(u16),
    UdpDport(u16),
    Mtu(u16),
    Mru(u16),
    Stats(Vec<L2tpStatsAttribute>),
    Ip6Saddr(Ipv6Addr),
    Ip6Daddr(Ipv6Addr),
    /// The tunnel uses zero UDP checksums on transmit for IPv6.
    UdpZeroCsum6Tx,
    /// The tunnel uses zero UDP checksums on receive for IPv6.
    UdpZeroCsum6Rx,
    Pad,
    Other(DefaultNla),
}

impl L2tpAttribute {
    /// Create a `L2TP_ATTR_COOKIE` attribute after checking its length.
    pub fn cookie(value: Vec<u8>) -> Result<Self, DecodeError> {
        validate_cookie_len(&value, "L2TP_ATTR_COOKIE")?;
        Ok(Self::Cookie(value))
    }

    /// Create a `L2TP_ATTR_PEER_COOKIE` attribute after checking its length.
    pub fn peer_cookie(value: Vec<u8>) -> Result<Self, DecodeError> {
        validate_cookie_len(&value, "L2TP_ATTR_PEER_COOKIE")?;
        Ok(Self::PeerCookie(value))
    }

    /// Create a `L2TP_ATTR_IFNAME` attribute after checking its length.
    pub fn if_name(value: impl Into<String>) -> Result<Self, DecodeError> {
        let value = value.into();
        validate_ifname(&value)?;
        Ok(Self::IfName(value))
    }
}

impl Nla for L2tpAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::PwType(_)
            | Self::EncapType(_)
            | Self::Offset(_)
            | Self::VlanId(_)
            | Self::UdpSport(_)
            | Self::UdpDport(_)
            | Self::Mtu(_)
            | Self::Mru(_) => 2,
            Self::DataSeq(_)
            | Self::L2SpecType(_)
            | Self::L2SpecLen(_)
            | Self::ProtoVersion(_)
            | Self::UdpCsum(_)
            | Self::RecvSeq(_)
            | Self::SendSeq(_)
            | Self::LnsMode(_)
            | Self::UsingIpsec(_) => 1,
            Self::ConnId(_)
            | Self::PeerConnId(_)
            | Self::SessionId(_)
            | Self::PeerSessionId(_)
            | Self::Debug(_)
            | Self::IpSaddr(_)
            | Self::IpDaddr(_)
            | Self::Fd(_) => 4,
            Self::RecvTimeout(_) => 8,
            Self::Ip6Saddr(_) | Self::Ip6Daddr(_) => 16,
            Self::Cookie(cookie) | Self::PeerCookie(cookie) => cookie.len(),
            Self::IfName(name) => name.len() + 1,
            Self::Stats(stats) => stats.as_slice().buffer_len(),
            Self::UdpZeroCsum6Tx | Self::UdpZeroCsum6Rx | Self::Pad => 0,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::PwType(_) => L2TP_ATTR_PW_TYPE,
            Self::EncapType(_) => L2TP_ATTR_ENCAP_TYPE,
            Self::Offset(_) => L2TP_ATTR_OFFSET,
            Self::DataSeq(_) => L2TP_ATTR_DATA_SEQ,
            Self::L2SpecType(_) => L2TP_ATTR_L2SPEC_TYPE,
            Self::L2SpecLen(_) => L2TP_ATTR_L2SPEC_LEN,
            Self::ProtoVersion(_) => L2TP_ATTR_PROTO_VERSION,
            Self::IfName(_) => L2TP_ATTR_IFNAME,
            Self::ConnId(_) => L2TP_ATTR_CONN_ID,
            Self::PeerConnId(_) => L2TP_ATTR_PEER_CONN_ID,
            Self::SessionId(_) => L2TP_ATTR_SESSION_ID,
            Self::PeerSessionId(_) => L2TP_ATTR_PEER_SESSION_ID,
            Self::UdpCsum(_) => L2TP_ATTR_UDP_CSUM,
            Self::VlanId(_) => L2TP_ATTR_VLAN_ID,
            Self::Cookie(_) => L2TP_ATTR_COOKIE,
            Self::PeerCookie(_) => L2TP_ATTR_PEER_COOKIE,
            Self::Debug(_) => L2TP_ATTR_DEBUG,
            Self::RecvSeq(_) => L2TP_ATTR_RECV_SEQ,
            Self::SendSeq(_) => L2TP_ATTR_SEND_SEQ,
            Self::LnsMode(_) => L2TP_ATTR_LNS_MODE,
            Self::UsingIpsec(_) => L2TP_ATTR_USING_IPSEC,
            Self::RecvTimeout(_) => L2TP_ATTR_RECV_TIMEOUT,
            Self::Fd(_) => L2TP_ATTR_FD,
            Self::IpSaddr(_) => L2TP_ATTR_IP_SADDR,
            Self::IpDaddr(_) => L2TP_ATTR_IP_DADDR,
            Self::UdpSport(_) => L2TP_ATTR_UDP_SPORT,
            Self::UdpDport(_) => L2TP_ATTR_UDP_DPORT,
            Self::Mtu(_) => L2TP_ATTR_MTU,
            Self::Mru(_) => L2TP_ATTR_MRU,
            Self::Stats(_) => L2TP_ATTR_STATS,
            Self::Ip6Saddr(_) => L2TP_ATTR_IP6_SADDR,
            Self::Ip6Daddr(_) => L2TP_ATTR_IP6_DADDR,
            Self::UdpZeroCsum6Tx => L2TP_ATTR_UDP_ZERO_CSUM6_TX,
            Self::UdpZeroCsum6Rx => L2TP_ATTR_UDP_ZERO_CSUM6_RX,
            Self::Pad => L2TP_ATTR_PAD,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::Offset(value)
            | Self::VlanId(value)
            | Self::UdpSport(value)
            | Self::UdpDport(value)
            | Self::Mtu(value)
            | Self::Mru(value) => emit_u16(buffer, *value).unwrap(),
            Self::PwType(value) => emit_u16(buffer, (*value).into()).unwrap(),
            Self::EncapType(value) => {
                emit_u16(buffer, (*value).into()).unwrap()
            }
            Self::DataSeq(value)
            | Self::L2SpecType(value)
            | Self::L2SpecLen(value)
            | Self::ProtoVersion(value)
            | Self::UdpCsum(value)
            | Self::RecvSeq(value)
            | Self::SendSeq(value)
            | Self::LnsMode(value)
            | Self::UsingIpsec(value) => buffer[0] = *value,
            Self::ConnId(value)
            | Self::PeerConnId(value)
            | Self::SessionId(value)
            | Self::PeerSessionId(value)
            | Self::Debug(value) => emit_u32(buffer, *value).unwrap(),
            Self::RecvTimeout(value) => emit_u64(buffer, *value).unwrap(),
            Self::Fd(value) => emit_i32(buffer, *value).unwrap(),
            Self::IpSaddr(value) | Self::IpDaddr(value) => {
                buffer.copy_from_slice(&value.octets())
            }
            Self::Ip6Saddr(value) | Self::Ip6Daddr(value) => {
                buffer.copy_from_slice(&value.octets())
            }
            Self::Cookie(cookie) | Self::PeerCookie(cookie) => {
                buffer.copy_from_slice(cookie)
            }
            Self::IfName(name) => {
                buffer[..name.len()].copy_from_slice(name.as_bytes());
                buffer[name.len()] = 0;
            }
            Self::Stats(stats) => stats.as_slice().emit(buffer),
            Self::UdpZeroCsum6Tx | Self::UdpZeroCsum6Rx | Self::Pad => (),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for L2tpAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            L2TP_ATTR_PW_TYPE => Self::PwType(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_PW_TYPE")?
                    .into(),
            ),
            L2TP_ATTR_ENCAP_TYPE => Self::EncapType(
                parse_u16(payload)
                    .context("invalid L2TP_ATTR_ENCAP_TYPE")?
                    .into(),
            ),
            L2TP_ATTR_OFFSET => Self::Offset(
                parse_u16(payload).context("invalid L2TP_ATTR_OFFSET")?,
            ),
            L2TP_ATTR_DATA_SEQ => Self::DataSeq(
                parse_u8(payload).context("invalid L2TP_ATTR_DATA_SEQ")?,
            ),
            L2TP_ATTR_L2SPEC_TYPE => Self::L2SpecType(
                parse_u8(payload).context("invalid L2TP_ATTR_L2SPEC_TYPE")?,
            ),
            L2TP_ATTR_L2SPEC_LEN => Self::L2SpecLen(
                parse_u8(payload).context("invalid L2TP_ATTR_L2SPEC_LEN")?,
            ),
            L2TP_ATTR_PROTO_VERSION => Self::ProtoVersion(
                parse_u8(payload).context("invalid L2TP_ATTR_PROTO_VERSION")?,
            ),
            L2TP_ATTR_IFNAME => Self::IfName(parse_ifname(payload)?),
            L2TP_ATTR_CONN_ID => Self::ConnId(
                parse_u32(payload).context("invalid L2TP_ATTR_CONN_ID")?,
            ),
            L2TP_ATTR_PEER_CONN_ID => Self::PeerConnId(
                parse_u32(payload).context("invalid L2TP_ATTR_PEER_CONN_ID")?,
            ),
            L2TP_ATTR_SESSION_ID => Self::SessionId(
                parse_u32(payload).context("invalid L2TP_ATTR_SESSION_ID")?,
            ),
            L2TP_ATTR_PEER_SESSION_ID => Self::PeerSessionId(
                parse_u32(payload)
                    .context("invalid L2TP_ATTR_PEER_SESSION_ID")?,
            ),
            L2TP_ATTR_UDP_CSUM => Self::UdpCsum(
                parse_u8(payload).context("invalid L2TP_ATTR_UDP_CSUM")?,
            ),
            L2TP_ATTR_VLAN_ID => Self::VlanId(
                parse_u16(payload).context("invalid L2TP_ATTR_VLAN_ID")?,
            ),
            L2TP_ATTR_COOKIE => {
                Self::Cookie(parse_cookie(payload, "L2TP_ATTR_COOKIE")?)
            }
            L2TP_ATTR_PEER_COOKIE => Self::PeerCookie(parse_cookie(
                payload,
                "L2TP_ATTR_PEER_COOKIE",
            )?),
            L2TP_ATTR_DEBUG => Self::Debug(
                parse_u32(payload).context("invalid L2TP_ATTR_DEBUG")?,
            ),
            L2TP_ATTR_RECV_SEQ => Self::RecvSeq(
                parse_u8(payload).context("invalid L2TP_ATTR_RECV_SEQ")?,
            ),
            L2TP_ATTR_SEND_SEQ => Self::SendSeq(
                parse_u8(payload).context("invalid L2TP_ATTR_SEND_SEQ")?,
            ),
            L2TP_ATTR_LNS_MODE => Self::LnsMode(
                parse_u8(payload).context("invalid L2TP_ATTR_LNS_MODE")?,
            ),
            L2TP_ATTR_USING_IPSEC => Self::UsingIpsec(
                parse_u8(payload).context("invalid L2TP_ATTR_USING_IPSEC")?,
            ),
            L2TP_ATTR_RECV_TIMEOUT => Self::RecvTimeout(
                parse_u64(payload).context("invalid L2TP_ATTR_RECV_TIMEOUT")?,
            ),
            L2TP_ATTR_FD => {
                Self::Fd(parse_i32(payload).context("invalid L2TP_ATTR_FD")?)
            }
            L2TP_ATTR_IP_SADDR => Self::IpSaddr(
                parse_ipv4(payload).context("invalid L2TP_ATTR_IP_SADDR")?,
            ),
            L2TP_ATTR_IP_DADDR => Self::IpDaddr(
                parse_ipv4(payload).context("invalid L2TP_ATTR_IP_DADDR")?,
            ),
            L2TP_ATTR_UDP_SPORT => Self::UdpSport(
                parse_u16(payload).context("invalid L2TP_ATTR_UDP_SPORT")?,
            ),
            L2TP_ATTR_UDP_DPORT => Self::UdpDport(
                parse_u16(payload).context("invalid L2TP_ATTR_UDP_DPORT")?,
            ),
            L2TP_ATTR_MTU => {
                Self::Mtu(parse_u16(payload).context("invalid L2TP_ATTR_MTU")?)
            }
            L2TP_ATTR_MRU => {
                Self::Mru(parse_u16(payload).context("invalid L2TP_ATTR_MRU")?)
            }
            L2TP_ATTR_STATS => Self::Stats(parse_stats(payload)?),
            L2TP_ATTR_IP6_SADDR => Self::Ip6Saddr(
                parse_ipv6(payload).context("invalid L2TP_ATTR_IP6_SADDR")?,
            ),
            L2TP_ATTR_IP6_DADDR => Self::Ip6Daddr(
                parse_ipv6(payload).context("invalid L2TP_ATTR_IP6_DADDR")?,
            ),
            L2TP_ATTR_UDP_ZERO_CSUM6_TX => Self::UdpZeroCsum6Tx,
            L2TP_ATTR_UDP_ZERO_CSUM6_RX => Self::UdpZeroCsum6Rx,
            L2TP_ATTR_PAD => Self::Pad,
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown L2TP NLA type {kind}"))?,
            ),
        })
    }
}

/// A counter of the nested `L2TP_ATTR_STATS` attribute.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpStatsAttribute {
    TxPackets(u64),
    TxBytes(u64),
    TxErrors(u64),
    RxPackets(u64),
    RxBytes(u64),
    RxSeqDiscards(u64),
    RxOosPackets(u64),
    RxErrors(u64),
    RxCookieDiscards(u64),
    RxInvalid(u64),
    Pad,
    Other(DefaultNla),
}

impl Nla for L2tpStatsAttribute {
    fn value_len(&self) -> usize {
        match self {
            Self::TxPackets(_)
            | Self::TxBytes(_)
            | Self::TxErrors(_)
            | Self::RxPackets(_)
            | Self::RxBytes(_)
            | Self::RxSeqDiscards(_)
            | Self::RxOosPackets(_)
            | Self::RxErrors(_)
            | Self::RxCookieDiscards(_)
            | Self::RxInvalid(_) => 8,
            Self::Pad => 0,
            Self::Other(attr) => attr.value_len(),
        }
    }

    fn kind(&self) -> u16 {
        match self {
            Self::TxPackets(_) => L2TP_ATTR_TX_PACKETS,
            Self::TxBytes(_) => L2TP_ATTR_TX_BYTES,
            Self::TxErrors(_) => L2TP_ATTR_TX_ERRORS,
            Self::RxPackets(_) => L2TP_ATTR_RX_PACKETS,
            Self::RxBytes(_) => L2TP_ATTR_RX_BYTES,
            Self::RxSeqDiscards(_) => L2TP_ATTR_RX_SEQ_DISCARDS,
            Self::RxOosPackets(_) => L2TP_ATTR_RX_OOS_PACKETS,
            Self::RxErrors(_) => L2TP_ATTR_RX_ERRORS,
            Self::RxCookieDiscards(_) => L2TP_ATTR_RX_COOKIE_DISCARDS,
            Self::RxInvalid(_) => L2TP_ATTR_RX_INVALID,
            Self::Pad => L2TP_ATTR_STATS_PAD,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, buffer: &mut [u8]) {
        match self {
            Self::TxPackets(value)
            | Self::TxBytes(value)
            | Self::TxErrors(value)
            | Self::RxPackets(value)
            | Self::RxBytes(value)
            | Self::RxSeqDiscards(value)
            | Self::RxOosPackets(value)
            | Self::RxErrors(value)
            | Self::RxCookieDiscards(value)
            | Self::RxInvalid(value) => emit_u64(buffer, *value).unwrap(),
            Self::Pad => (),
            Self::Other(attr) => attr.emit_value(buffer),
        }
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> Parseable<NlaBuffer<&'a T>>
    for L2tpStatsAttribute
{
    fn parse(buf: &NlaBuffer<&'a T>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            L2TP_ATTR_TX_PACKETS => Self::TxPackets(
                parse_u64(payload).context("invalid L2TP_ATTR_TX_PACKETS")?,
            ),
            L2TP_ATTR_TX_BYTES => Self::TxBytes(
                parse_u64(payload).context("invalid L2TP_ATTR_TX_BYTES")?,
            ),
            L2TP_ATTR_TX_ERRORS => Self::TxErrors(
                parse_u64(payload).context("invalid L2TP_ATTR_TX_ERRORS")?,
            ),
            L2TP_ATTR_RX_PACKETS => Self::RxPackets(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_PACKETS")?,
            ),
            L2TP_ATTR_RX_BYTES => Self::RxBytes(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_BYTES")?,
            ),
            L2TP_ATTR_RX_SEQ_DISCARDS => Self::RxSeqDiscards(
                parse_u64(payload)
                    .context("invalid L2TP_ATTR_RX_SEQ_DISCARDS")?,
            ),
            L2TP_ATTR_RX_OOS_PACKETS => Self::RxOosPackets(
                parse_u64(payload)
                    .context("invalid L2TP_ATTR_RX_OOS_PACKETS")?,
            ),
            L2TP_ATTR_RX_ERRORS => Self::RxErrors(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_ERRORS")?,
            ),
            L2TP_ATTR_RX_COOKIE_DISCARDS => Self::RxCookieDiscards(
                parse_u64(payload)
                    .context("invalid L2TP_ATTR_RX_COOKIE_DISCARDS")?,
            ),
            L2TP_ATTR_RX_INVALID => Self::RxInvalid(
                parse_u64(payload).context("invalid L2TP_ATTR_RX_INVALID")?,
            ),
            L2TP_ATTR_STATS_PAD => Self::Pad,
            kind => Self::Other(
                DefaultNla::parse(buf)
                    .context(format!("unknown L2TP stats NLA type {kind}"))?,
            ),
        })
    }
}

fn parse_ifname(payload: &[u8]) -> Result<String, DecodeError> {
    let name = parse_string(payload).context("invalid L2TP_ATTR_IFNAME")?;
    validate_ifname(&name)?;
    Ok(name)
}

fn validate_ifname(name: &str) -> Result<(), DecodeError> {
    if name.len() > L2TP_IFNAME_MAX_LEN {
        Err(DecodeError::from(format!(
            "L2TP_ATTR_IFNAME is too long: {} > {} bytes",
            name.len(),
            L2TP_IFNAME_MAX_LEN
        )))
    } else {
        Ok(())
    }
}

fn parse_cookie(
    payload: &[u8],
    attribute: &str,
) -> Result<Vec<u8>, DecodeError> {
    validate_cookie_len(payload, attribute)?;
    Ok(payload.to_vec())
}

fn validate_cookie_len(
    payload: &[u8],
    attribute: &str,
) -> Result<(), DecodeError> {
    match payload.len() {
        0 | 4 | L2TP_COOKIE_MAX_LEN => Ok(()),
        len => Err(DecodeError::from(format!(
            "{attribute} has invalid length {len}: must be 0, 4 or 8 bytes"
        ))),
    }
}

fn parse_stats(payload: &[u8]) -> Result<Vec<L2tpStatsAttribute>, DecodeError> {
    let mut stats = Vec::new();
    for nla in NlasIterator::new(payload) {
        let nla = &nla.context("failed to parse L2TP stats attributes")?;
        stats.push(L2tpStatsAttribute::parse(nla)?);
    }
    Ok(stats)
}

fn parse_ipv4(payload: &[u8]) -> Result<Ipv4Addr, DecodeError> {
    let octets: [u8; 4] =
        payload
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| {
                DecodeError::from(e.to_string())
            })?;
    Ok(Ipv4Addr::from(octets))
}

fn parse_ipv6(payload: &[u8]) -> Result<Ipv6Addr, DecodeError> {
    let octets: [u8; 16] =
        payload
            .try_into()
            .map_err(|e: std::array::TryFromSliceError| {
                DecodeError::from(e.to_string())
            })?;
    Ok(Ipv6Addr::from(octets))
}
