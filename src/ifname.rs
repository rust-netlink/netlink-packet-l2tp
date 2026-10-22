// SPDX-License-Identifier: MIT

use std::{borrow::Cow, fmt, str::FromStr, str::Utf8Error};

use netlink_packet_core::DecodeError;

/// `IFNAMSIZ` of the kernel: the longest interface name plus its NUL.
const IFNAMSIZ: usize = 16;

/// A Linux network interface name, as carried by `L2TP_ATTR_IFNAME`.
///
/// The name is stored like the kernel's `char[IFNAMSIZ]`: up to 15 bytes
/// followed by NUL padding. Linux interface names are bytes and need not be
/// valid UTF-8.
///
/// Every value satisfies the rules the kernel enforces on names:
/// `L2TP_ATTR_IFNAME` must fit in `IFNAMSIZ` including its NUL, and
/// `dev_valid_name()` rejects empty names, `.`, `..`, and names containing
/// `/`, `:` or whitespace. The kernel's `isspace()` also matches byte 0xa0,
/// which occurs inside UTF-8 sequences such as `à` (0xc3 0xa0).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct L2tpIfName([u8; IFNAMSIZ]);

impl L2tpIfName {
    /// Create an interface name from its bytes, without a terminating NUL.
    pub fn new(name: impl AsRef<[u8]>) -> Result<Self, DecodeError> {
        let name = name.as_ref();
        validate(name)?;
        let mut buffer = [0; IFNAMSIZ];
        buffer[..name.len()].copy_from_slice(name);
        Ok(Self(buffer))
    }

    /// Create an interface name from anything that can be borrowed as a
    /// `str`, such as `Cow<str>` or `Box<str>`.
    pub fn from_str_ref(name: impl AsRef<str>) -> Result<Self, DecodeError> {
        Self::new(name.as_ref())
    }

    /// Create an interface name from anything convertible into a `String`,
    /// such as a `char`.
    pub fn from_string(name: impl Into<String>) -> Result<Self, DecodeError> {
        Self::new(name.into())
    }

    /// The name without NUL padding.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0[..self.len()]
    }

    /// The name as the kernel's NUL-padded `char[IFNAMSIZ]` buffer.
    pub fn as_array(&self) -> &[u8; IFNAMSIZ] {
        &self.0
    }

    /// The name as a `str`, if it is valid UTF-8.
    pub fn to_str(&self) -> Result<&str, Utf8Error> {
        std::str::from_utf8(self.as_bytes())
    }

    /// The name as a `str`, replacing invalid UTF-8 with U+FFFD.
    pub fn to_string_lossy(&self) -> Cow<'_, str> {
        String::from_utf8_lossy(self.as_bytes())
    }

    // A valid name always ends before the last byte of the buffer.
    fn len(&self) -> usize {
        self.0
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(IFNAMSIZ)
    }

    // The kernel reads `L2TP_ATTR_IFNAME` as a C string, ignoring anything
    // after the first NUL. Unterminated payloads are accepted for
    // compatibility with earlier releases.
    pub(crate) fn parse(payload: &[u8]) -> Result<Self, DecodeError> {
        let end = payload
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(payload.len());
        Self::new(&payload[..end])
    }

    // Length of the attribute value, the name plus its terminating NUL.
    pub(crate) fn value_len(&self) -> usize {
        self.len() + 1
    }

    pub(crate) fn emit(&self, buffer: &mut [u8]) {
        let len = self.len();
        buffer[..len].copy_from_slice(&self.0[..len]);
        buffer[len] = 0;
    }
}

fn validate(name: &[u8]) -> Result<(), DecodeError> {
    let error = |reason: &str| {
        Err(DecodeError::from(format!(
            "invalid interface name \"{}\": {reason}",
            name.escape_ascii()
        )))
    };
    if name.is_empty() {
        error("empty name")
    } else if name.len() >= IFNAMSIZ {
        error(&format!(
            "too long: {} > {} bytes",
            name.len(),
            IFNAMSIZ - 1
        ))
    } else if name == b"." || name == b".." {
        error("reserved name")
    } else if let Some(byte) = name.iter().find(|byte| is_invalid_byte(**byte))
    {
        error(&format!("contains invalid byte {byte:#04x}"))
    } else {
        Ok(())
    }
}

fn is_invalid_byte(byte: u8) -> bool {
    matches!(byte, 0 | b'/' | b':' | b'\t'..=b'\r' | b' ' | 0xa0)
}

impl fmt::Debug for L2tpIfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "L2tpIfName(\"{}\")", self.as_bytes().escape_ascii())
    }
}

/// Lossy: invalid UTF-8 is shown as U+FFFD.
impl fmt::Display for L2tpIfName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_string_lossy())
    }
}

impl AsRef<[u8]> for L2tpIfName {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl From<L2tpIfName> for [u8; IFNAMSIZ] {
    fn from(name: L2tpIfName) -> Self {
        name.0
    }
}

impl FromStr for L2tpIfName {
    type Err = DecodeError;

    fn from_str(name: &str) -> Result<Self, Self::Err> {
        Self::new(name)
    }
}

impl TryFrom<&str> for L2tpIfName {
    type Error = DecodeError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl TryFrom<String> for L2tpIfName {
    type Error = DecodeError;

    fn try_from(name: String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl TryFrom<&String> for L2tpIfName {
    type Error = DecodeError;

    fn try_from(name: &String) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl TryFrom<&[u8]> for L2tpIfName {
    type Error = DecodeError;

    fn try_from(name: &[u8]) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

impl TryFrom<Vec<u8>> for L2tpIfName {
    type Error = DecodeError;

    fn try_from(name: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(name)
    }
}

/// Takes the bytes before the first NUL as the name, as the kernel does.
impl TryFrom<[u8; IFNAMSIZ]> for L2tpIfName {
    type Error = DecodeError;

    fn try_from(buffer: [u8; IFNAMSIZ]) -> Result<Self, Self::Error> {
        Self::parse(&buffer)
    }
}
