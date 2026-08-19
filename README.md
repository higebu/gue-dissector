# gue-dissector

A Wireshark Lua dissector for **Generic UDP Encapsulation (GUE)** on UDP port 6080,
covering both `draft-ietf-intarea-gue-09` and the flags the Linux kernel actually
puts on the wire.

## Why

`draft-ietf-intarea-gue` expired at revision 09 (2019-10-26) without becoming an
RFC, and none of the IANA registries it asked for were ever created. Wireshark
therefore has no built-in GUE dissector, and GUE traffic shows up as an
undissected UDP payload.

The encapsulation is deployed anyway. Linux implements it as part of foo-over-UDP
(`net/ipv4/fou.c`, `include/net/gue.h`), reachable through `ip fou add port 6080 gue`,
and GitHub's GLB load balancer is built on it.

## Install

```
cp gue.lua ~/.local/lib/wireshark/plugins/
```

The exact directory is under **Help → About Wireshark → Folders → Personal Lua Plugins**.

For a one-off run without installing:

```
tshark -X lua_script:gue.lua -r capture.pcap
```

The UDP port defaults to 6080 and can be changed in
**Preferences → Protocols → GUE**.

> **Note:** this plugin registers a protocol named `gue`. If your Wireshark ever
> gains a built-in GUE dissector, the two collide and the plugin fails to load.
> Remove `gue.lua` at that point.

## What it decodes

### Variant 0

The four-byte base header (variant, C bit, Hlen, Proto/Ctype, Flags), then the
payload handed to the `ip.proto` dissector table, so `IP → UDP → GUE → IP → TCP`
chains open up naturally.

* **Hlen** counts 32-bit words *after* the first four bytes, so the header is
  `4 + 4 * Hlen` bytes. The tree spells the byte count out to save you the arithmetic.
* **Protocol 59** ("no next header") is deliberately left unparsed, as section
  3.2.1 requires.
* Header space the extension fields do not use is shown as **surplus space**
  (section 3.4).
* **Control messages** (C bit set) show the control type, and for the
  experimental type 255 the 32-bit **ExID** that sits at the head of the payload,
  outside of Hlen.

### Variant 1

No GUE header at all — the first four bits select the IPv4 or IPv6 dissector for
the whole UDP payload. The variant bits are shown over the byte they share with
the IP version field.

### Linux flags

The base draft assigns no flag bits. Linux defines one standard flag, and drops
any packet carrying a flag it does not know:

```c
/* include/net/gue.h */
#define GUE_FLAG_PRIV       htons(1<<0)     /* private flags are in the options */
#define GUE_LEN_PRIV        4
#define GUE_FLAGS_ALL       (GUE_FLAG_PRIV)

#define GUE_PFLAG_REMCSUM   htonl(1U << 31) /* remote checksum offload */
#define GUE_PLEN_REMCSUM    4
#define GUE_PFLAGS_ALL      (GUE_PFLAG_REMCSUM)
```

This dissector decodes that set: the private flags word and the remote checksum
offload field behind it. The two halves of that field are where the inner
checksum computation starts and where the checksum itself sits, both relative to
the encapsulated packet (`__gue_build_header()` in `net/ipv4/fou_core.c`):

```c
csum_start -= hdrlen;
pd[0] = htons(csum_start);
pd[1] = htons(csum_start + skb->csum_offset);
```

Extension fields are laid out in flag order, so a single unrecognised flag makes
every offset in the option area indeterminate. In that case the area is left
undecoded rather than misparsed.

Here is a real header Linux emitted, from `captures/gue-linux-remcsum.pcap`:

```
02 04 00 01 | 80 00 00 00 | 00 14 00 1a | 45 00 00 28 ...
^^ ^^ ^^^^^   ^^^^^^^^^^^   ^^^^^ ^^^^^   inner IPv4
|  |  |       |             |     `- Checksum offset = 26
|  |  |       |             `- Checksum start = 20
|  |  |       `- private flags: GUE_PFLAG_REMCSUM
|  |  `- flags = 0x0001 : GUE_FLAG_PRIV
|  `- proto = 4 (IPIP)
`- variant 0, C=0, Hlen=2 -> header length 4 + 2*4 = 12 bytes
```

which the dissector renders as:

```
Generic UDP Encapsulation
    00.. .... = Variant: GUE header (0)
    ..0. .... = Message type: Data message
    ...0 0010 = Header length: 2 (12 bytes)
    Proto: IPv4 (4)
    Flags: 0x0001
        0000 0000 0000 000. = Reserved: 0x0000
        .... .... .... ...1 = Private flags present: True
    Private flags: 0x80000000
        1... .... .... .... .... .... .... .... = Remote checksum offload: True
        .000 0000 0000 0000 0000 0000 0000 0000 = Reserved: 0x00000000
    Checksum start: 20
    Checksum offset: 26
Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2
```

### Expert infos

| Filter | Meaning |
| --- | --- |
| `gue.variant.reserved` | Variant 2 or 3 |
| `gue.variant.direct.bad_version` | Variant 1 payload is neither IPv4 nor IPv6 |
| `gue.hlen.invalid` | Header length runs past the end of the packet |
| `gue.hlen.too_short` | Header too short for the extension fields the flags call for |
| `gue.flags.unknown` | A flag Linux would drop the packet for |
| `gue.priv_flags.unknown` | Same, one level down |
| `gue.exid.missing` | Control type 255 without its 4-byte ExID |

## Captures

`captures/` holds two captures taken from a real Linux GUE tunnel, not synthesised:

| File | Contents |
| --- | --- |
| `gue-linux-basic.pcap` | ICMP echo over IPv4-in-GUE, plain header (Hlen 0) |
| `gue-linux-remcsum.pcap` | UDP over IPv4-in-GUE with private flags and remote checksum offload |

Regenerate them with `tools/capture-gue.sh`, which builds an isolated pair of
network namespaces and tears them down afterwards:

```
sudo ./tools/capture-gue.sh captures/gue-linux-basic.pcap
sudo ./tools/capture-gue.sh captures/gue-linux-remcsum.pcap --remcsum
```

Remote checksum offload only engages when the inner packet has a checksum waiting
to be offloaded, which is why the `--remcsum` mode sends UDP rather than ICMP:

```c
/* __gue_build_header() */
if ((e->flags & TUNNEL_ENCAP_FLAG_REMCSUM) &&
    skb->ip_summed == CHECKSUM_PARTIAL) {
```

The tunnel it sets up is, in short:

```sh
ip netns exec gue-a ip fou add port 6080 gue
ip netns exec gue-a ip link add name gue4 type ipip \
    remote 198.51.100.2 local 198.51.100.1 \
    encap gue encap-sport 6080 encap-dport 6080 encap-remcsum
```

## Development

Tests run the dissector over the captures in `captures/` with `tshark` and
check the fields it produces, so they cover the captures as much as the
dissector. They need a `tshark` built with Lua, which is the case for the
Debian and Ubuntu packages:

```
uv run pytest
```

Set `TSHARK` to use a specific binary. Without Lua support the tests skip
themselves, and CI fails the build separately if the runner's `tshark` lacks
it.

Formatting:

```
uv run ruff check .
uv run ruff format .
stylua .
```

StyLua is not installable through `uv`: its `release-gitter` build backend
needs the optional PEP 517 `prepare_metadata_for_build_wheel` hook, which uv
does not call, so `uv tool install git+...` fails with `Cannot build wheel
without metadata_directory`. Use `pip install git+https://github.com/johnnymorganz/stylua`,
a [release binary](https://github.com/JohnnyMorganz/StyLua/releases), or
`cargo install stylua`. CI uses the upstream action instead.

## References

* [draft-ietf-intarea-gue-09](https://datatracker.ietf.org/doc/draft-ietf-intarea-gue/) — Generic UDP Encapsulation (expired)
* [`include/net/gue.h`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/include/net/gue.h) — the Linux header layout
* [`net/ipv4/fou_core.c`](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/net/ipv4/fou_core.c) — the Linux send and receive paths
* [`ip-fou(8)`](https://man7.org/linux/man-pages/man8/ip-fou.8.html)

## License

GPL-2.0-or-later, matching Wireshark. See [LICENSE](LICENSE).
