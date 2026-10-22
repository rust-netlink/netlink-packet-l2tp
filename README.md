# netlink-packet-l2tp

L2TP generic netlink packet definitions for the
[rust-netlink](https://github.com/rust-netlink) project.

This crate only parses and emits the netlink payload of the `l2tp` generic
netlink family (`include/uapi/linux/l2tp.h` in the Linux kernel). To talk to
the kernel, use the [`nl-l2tp`](https://crates.io/crates/nl-l2tp) crate, or
the [`l2tp`](https://crates.io/crates/l2tp) crate, a high-level facade over
this one that manages L2TP tunnels and sessions without exposing netlink
messages.

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

## Interface names

`L2tpAttribute::IfName` holds an `L2tpIfName`, stored like the kernel's
`char[IFNAMSIZ]`: up to 15 bytes followed by NUL padding. Linux interface names
are bytes, so names that are not valid UTF-8 are supported; use `as_bytes()`,
`to_str()` or `to_string_lossy()` to read one.

Create names with `L2tpIfName::new` (bytes), `from_str_ref` (anything
implementing `AsRef<str>`), `from_string` (anything implementing
`Into<String>`), `TryFrom` or `str::parse`, or with `L2tpAttribute::if_name`.
Every `L2tpIfName` satisfies the rules the kernel enforces: 1 to 15 bytes, not
`.` or `..`, and free of NUL, `/`, `:` and whitespace bytes, as checked by
`dev_valid_name()`. The kernel's `isspace()` also matches byte 0xa0, so names
containing characters such as `à` (UTF-8 `0xc3 0xa0`) are rejected too.

When parsing, the payload must fit `IFNAMSIZ` (16 bytes) including one
trailing NUL, as the kernel's netlink policy requires, and the name is the
part of it before the first NUL, as the kernel reads it. Unterminated names
are accepted for compatibility.

## Validation and unchecked values

Use `L2tpAttribute::cookie` and `L2tpAttribute::peer_cookie` for user-provided
cookies. These constructors return an error for cookies whose length is
neither 0, 4, nor 8 bytes.

Constructing or mutating the public enum variants directly bypasses the
checked constructors. Emission checks these values, including known types
supplied through `Other`, and panics on invalid input. Attributes must fit the
16-bit netlink length field, including their four-byte header; statistics
containers must also fit after accounting for the alignment of their children.
Oversized attributes panic during length calculation or emission rather than
truncating the length field. `L2tpMessage::emit` checks all attributes and the
destination buffer size before writing the message payload.

The `Emitable` and `Nla` trait methods are infallible. Use the checked
constructors, and allocate emission buffers with `buffer_len()` only after
bounding any directly supplied raw attributes or statistics collections.

Parsing rejects malformed attribute headers, invalid interface names, and
nonempty flag or padding payloads. Unknown attributes and enum values remain
supported; validation does not impose command-specific kernel policy or check
whether a socket file descriptor is open.

License: MIT
