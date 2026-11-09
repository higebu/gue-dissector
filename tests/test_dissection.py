"""Check the dissector against the captures in captures/.

Both captures came out of a real Linux GUE tunnel, so these tests pin down
what the kernel actually sends as much as what the dissector makes of it.
Every expectation here was read off the capture, not assumed.
"""

import pytest

BASIC = "gue-linux-basic.pcap"
REMCSUM = "gue-linux-remcsum.pcap"

# Every expert info gue.lua registers, without the protocol name in front.
# If one of these fires on a capture taken from the kernel, either the capture
# or the dissector is wrong.
EXPERT_INFOS = (
    "variant.reserved",
    "variant.direct.bad_version",
    "hlen.invalid",
    "hlen.too_short",
    "flags.unknown",
    "priv_flags.unknown",
    "exid.missing",
)


def header_fields(gue):
    # "control" is deliberately absent: tshark renders FT_BOOLEAN as 0/1 in
    # some versions and False/True in others, so it is asserted with a display
    # filter instead of a field value.
    return (f"{gue}.variant", f"{gue}.hlen", f"{gue}.proto", f"{gue}.flags")


def protocol_chains(dissect, capture, display_filter=None):
    return [row[0] for row in dissect(capture, ("frame.protocols",), display_filter)]


class TestBasicCapture:
    """ICMP echo over IPv4-in-GUE, plain header."""

    def test_every_frame_is_a_bare_variant_0_header(self, dissect, gue):
        rows = dissect(BASIC, header_fields(gue))
        assert len(rows) == 6
        # variant 0, Hlen 0, proto 4 (IPIP), no flags
        assert rows == [["0", "0", "4", "0x0000"]] * 6

    def test_every_frame_is_a_data_message(self, dissect, gue):
        assert len(dissect(BASIC, ("frame.number",), f"{gue}.control == 0")) == 6

    def test_inner_icmp_is_dissected(self, dissect):
        rows = dissect(BASIC, ("ip.src", "icmp.type"))
        # ip.src lists the underlay address first, then the tunnelled one.
        assert (
            rows
            == [
                ["198.51.100.1,10.0.0.1", "8"],
                ["198.51.100.2,10.0.0.2", "0"],
            ]
            * 3
        )

    def test_protocol_chain(self, dissect, gue):
        chains = protocol_chains(dissect, BASIC)
        # Whether a trailing "data" layer is appended for the ICMP payload
        # varies between Wireshark versions, so only the hand-off is pinned.
        assert len(chains) == 6
        assert all(c.startswith(f"eth:ethertype:ip:udp:{gue}:ip:icmp") for c in chains), chains


class TestRemcsumCapture:
    """UDP over IPv4-in-GUE with the private flags and remote checksum offload.

    Nothing is listening on the far side, so the odd frames are the requests
    carrying the extension and the even ones are ICMP port-unreachable replies
    coming back through the tunnel without it.
    """

    def test_requests_carry_private_flags_and_remcsum(self, dissect, gue):
        rows = dissect(
            REMCSUM,
            (
                *header_fields(gue),
                f"{gue}.priv_flags",
                f"{gue}.remcsum.start",
                f"{gue}.remcsum.offset",
            ),
            display_filter=f"{gue}.flags.priv == 1",
        )
        assert len(rows) == 3
        # Hlen 2 covers the private flags word plus the 4-byte remcsum field.
        # Checksum start 20 is the inner UDP header (right after a 20-byte IPv4
        # header) and offset 26 is its checksum field.
        assert rows == [["0", "2", "4", "0x0001", "0x80000000", "20", "26"]] * 3

    def test_replies_carry_no_extension(self, dissect, gue):
        rows = dissect(REMCSUM, header_fields(gue), display_filter=f"{gue}.flags.priv == 0")
        assert rows == [["0", "0", "4", "0x0000"]] * 3

    def test_inner_udp_is_dissected(self, dissect, gue):
        chains = protocol_chains(dissect, REMCSUM, f"{gue}.flags.priv == 1")
        assert len(chains) == 3
        assert all(c.startswith(f"eth:ethertype:ip:udp:{gue}:ip:udp") for c in chains), chains

    def test_surplus_space_is_not_reported(self, dissect, gue):
        """Hlen 2 is fully consumed by the extension, so nothing is left over."""
        rows = dissect(REMCSUM, (f"{gue}.surplus",), display_filter=f"{gue}.surplus")
        assert rows == []


class TestTruncatedCapture:
    """A capture cut short by the snaplen must not blow up.

    Asking a Tvb for more bytes than the snaplen kept raises a Lua error
    rather than the bounds exception a built-in dissector gets, so every
    range has to be capped by the captured length. Snaplens 44 to 54 leave
    the GUE header itself half-read.

    A sub-dissector handed a truncated payload still surfaces a Lua error of
    its own ("Dissector_call: Malformed frame"), which Wireshark's Lua API
    gives no way to avoid; that is not what these tests are about.
    """

    @pytest.mark.parametrize("snaplen", [44, 46, 48, 50, 54])
    def test_no_out_of_bounds_error(self, dissect, truncated_capture, snaplen):
        rows = dissect(truncated_capture(REMCSUM, snaplen), ("_ws.expert.message",))
        assert rows, f"snaplen {snaplen} produced no packets at all"
        for row in rows:
            assert "out of bounds" not in row[0], row

    @pytest.mark.parametrize("snaplen", [44, 46, 48, 50, 54])
    def test_header_is_still_reported(self, dissect, gue, truncated_capture, snaplen):
        """What did fit in the capture is still decoded."""
        rows = dissect(truncated_capture(REMCSUM, snaplen), (f"{gue}.hlen",))
        assert [row[0] for row in rows] == ["2", "0"] * 3


@pytest.mark.parametrize("capture", [BASIC, REMCSUM])
class TestCaptureSanity:
    def test_six_frames_all_gue(self, dissect, gue, capture):
        assert len(dissect(capture, ("frame.number",), display_filter=gue)) == 6

    def test_tunnel_endpoints(self, dissect, capture):
        """The underlay is 198.51.100.0/24 and the overlay is 10.0.0.0/24."""
        rows = dissect(capture, ("ip.src", "ip.dst"))
        for src, dst in rows:
            assert src.startswith("198.51.100.")
            assert dst.startswith("198.51.100.")
            assert "10.0.0." in src
            assert "10.0.0." in dst

    def test_udp_port_is_the_iana_assignment(self, dissect, capture):
        rows = dissect(capture, ("udp.dstport",))
        assert all(row[0].startswith("6080") for row in rows)

    @pytest.mark.parametrize("expert", EXPERT_INFOS)
    def test_no_expert_info_fires(self, dissect, gue, capture, expert):
        assert dissect(capture, ("frame.number",), display_filter=f"{gue}.{expert}") == []
