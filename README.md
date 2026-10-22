# netlink-packet-l2tp

L2TP generic netlink packet definitions for the
[rust-netlink](https://github.com/rust-netlink) project.

This crate only parses and emits the netlink payload of the `l2tp` generic
netlink family (`include/uapi/linux/l2tp.h` in the Linux kernel). To talk to
the kernel, use the `nl-l2tp` crate.

```rust,no_run
use netlink_packet_l2tp::{
    L2tpAttribute, L2tpCmd, L2tpEncapType, L2tpMessage,
};

let message = L2tpMessage {
    cmd: L2tpCmd::TunnelCreate,
    attributes: vec![
        L2tpAttribute::ConnId(1000),
        L2tpAttribute::PeerConnId(2000),
        L2tpAttribute::ProtoVersion(3),
        L2tpAttribute::EncapType(L2tpEncapType::Udp),
    ],
};
```

## Validation and unchecked values

Use `L2tpAttribute::if_name`, `L2tpAttribute::cookie`, and
`L2tpAttribute::peer_cookie` for user-provided values. These constructors return
an error for cookies whose length is neither 0, 4, nor 8 bytes, and for
interface names the kernel would reject. Interface names follow
`dev_valid_name()` of the kernel: 1 to 15 bytes, not `.` or `..`, and free of
NUL, `/`, `:` and whitespace bytes. The kernel's `isspace()` also matches byte
0xa0, so names containing characters such as `à` (UTF-8 `0xc3 0xa0`) are
rejected too.

The public enum variants remain available for compatibility with 0.3.0.
Constructing or mutating them directly bypasses the checked constructors.
Emission now checks these values, including known types supplied through
`Other`, and panics on invalid input. Attributes must fit the 16-bit netlink
length field, including their four-byte header; statistics containers must
also fit after accounting for the alignment of their children. Oversized
attributes panic during length calculation or emission rather than truncating
the length field. `L2tpMessage::emit` checks all attributes and the destination
buffer size before writing the message payload.

Deferred API work: fallible validation and serialization methods would let
callers handle invalid directly constructed values, oversized attributes, and
short output buffers with `Result` instead of panics. Those methods are not
added in 0.3.1. Until then, use the existing checked constructors and allocate
emission buffers with `buffer_len()` only after bounding any directly supplied
raw attributes or statistics collections. The existing `Emitable` and `Nla`
trait methods remain infallible.

Also deferred to 0.4.0: `L2tpAttribute::IfName` holds a `String`, so interface
names that are not valid UTF-8 cannot be represented, and parsing a message
containing one fails. 0.4.0 will store interface names as `[u8; 16]`, the
kernel's `IFNAMSIZ` buffer.

Parsing rejects malformed attribute headers, invalid interface names, and
nonempty flag or padding payloads. For compatibility, interface names without
a trailing NUL are still accepted, as are names followed by NUL padding. Unknown attributes and enum
values remain supported; validation does not impose command-specific kernel
policy or check whether a socket file descriptor is open.

License: MIT
