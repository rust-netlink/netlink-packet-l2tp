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
an error for interface names containing NUL bytes or more than 15 bytes, and
for cookies whose length is neither 0, 4, nor 8 bytes.

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

Parsing rejects malformed attribute headers, embedded NUL bytes in interface
names, and nonempty flag or padding payloads. For compatibility, interface
names without a trailing NUL are still accepted. Unknown attributes and enum
values remain supported; validation does not impose command-specific kernel
policy or check whether a socket file descriptor is open.

License: MIT
