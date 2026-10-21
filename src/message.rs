// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    DecodeError, Emitable, ErrorContext, NlasIterator, Parseable,
    ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::L2tpAttribute;

// `L2TP_CMD_*` of the kernel, exposed through the `L2tpCmd` enum, the raw
// values stay private.
const L2TP_CMD_NOOP: u8 = 0;
const L2TP_CMD_TUNNEL_CREATE: u8 = 1;
const L2TP_CMD_TUNNEL_DELETE: u8 = 2;
const L2TP_CMD_TUNNEL_MODIFY: u8 = 3;
const L2TP_CMD_TUNNEL_GET: u8 = 4;
const L2TP_CMD_SESSION_CREATE: u8 = 5;
const L2TP_CMD_SESSION_DELETE: u8 = 6;
const L2TP_CMD_SESSION_MODIFY: u8 = 7;
const L2TP_CMD_SESSION_GET: u8 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2tpCmd {
    Noop,
    TunnelCreate,
    TunnelDelete,
    TunnelModify,
    TunnelGet,
    SessionCreate,
    SessionDelete,
    SessionModify,
    SessionGet,
    Other(u8),
}

impl From<L2tpCmd> for u8 {
    fn from(cmd: L2tpCmd) -> Self {
        match cmd {
            L2tpCmd::Noop => L2TP_CMD_NOOP,
            L2tpCmd::TunnelCreate => L2TP_CMD_TUNNEL_CREATE,
            L2tpCmd::TunnelDelete => L2TP_CMD_TUNNEL_DELETE,
            L2tpCmd::TunnelModify => L2TP_CMD_TUNNEL_MODIFY,
            L2tpCmd::TunnelGet => L2TP_CMD_TUNNEL_GET,
            L2tpCmd::SessionCreate => L2TP_CMD_SESSION_CREATE,
            L2tpCmd::SessionDelete => L2TP_CMD_SESSION_DELETE,
            L2tpCmd::SessionModify => L2TP_CMD_SESSION_MODIFY,
            L2tpCmd::SessionGet => L2TP_CMD_SESSION_GET,
            L2tpCmd::Other(cmd) => cmd,
        }
    }
}

impl From<u8> for L2tpCmd {
    fn from(value: u8) -> Self {
        match value {
            L2TP_CMD_NOOP => Self::Noop,
            L2TP_CMD_TUNNEL_CREATE => Self::TunnelCreate,
            L2TP_CMD_TUNNEL_DELETE => Self::TunnelDelete,
            L2TP_CMD_TUNNEL_MODIFY => Self::TunnelModify,
            L2TP_CMD_TUNNEL_GET => Self::TunnelGet,
            L2TP_CMD_SESSION_CREATE => Self::SessionCreate,
            L2TP_CMD_SESSION_DELETE => Self::SessionDelete,
            L2TP_CMD_SESSION_MODIFY => Self::SessionModify,
            L2TP_CMD_SESSION_GET => Self::SessionGet,
            cmd => Self::Other(cmd),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct L2tpMessage {
    pub cmd: L2tpCmd,
    pub attributes: Vec<L2tpAttribute>,
}

impl L2tpMessage {
    pub fn new(cmd: L2tpCmd) -> Self {
        Self {
            cmd,
            attributes: Vec::new(),
        }
    }
}

impl GenlFamily for L2tpMessage {
    fn family_name() -> &'static str {
        "l2tp"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl Emitable for L2tpMessage {
    fn emit(&self, buffer: &mut [u8]) {
        // Validate the entire message before writing any attribute. Public
        // enum variants can bypass the checked attribute constructors.
        for attribute in &self.attributes {
            attribute
                .validate()
                .expect("invalid L2TP message attribute");
        }
        assert!(
            buffer.len() >= self.buffer_len(),
            "L2TP buffer is too small"
        );
        self.attributes.as_slice().emit(buffer)
    }

    fn buffer_len(&self) -> usize {
        self.attributes.as_slice().buffer_len()
    }
}

impl ParseableParametrized<[u8], GenlHeader> for L2tpMessage {
    fn parse_with_param(
        buf: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(Self {
            cmd: header.cmd.into(),
            attributes: parse_attributes(buf)?,
        })
    }
}

fn parse_attributes(buf: &[u8]) -> Result<Vec<L2tpAttribute>, DecodeError> {
    let mut attributes = Vec::new();
    let error_msg = "failed to parse l2tp netlink attributes";
    for nla in NlasIterator::new(buf) {
        let nla = &nla.context(error_msg)?;
        attributes.push(L2tpAttribute::parse(nla)?);
    }
    Ok(attributes)
}
