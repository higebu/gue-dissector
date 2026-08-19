"""Check the dissector against the captures in captures/.

Both captures came out of a real Linux GUE tunnel, so these tests pin down
what the kernel actually sends as much as what the dissector makes of it.
Every expectation here was read off the capture, not assumed.
"""

import pytest

BASIC = "gue-linux-basic.pcap"
REMCSUM = "gue-linux-remcsum.pcap"

# Every expert info gue.lua registers.  If one of these fires on a capture
# taken from the kernel, either the capture or the dissector is wrong.
EXPERT_INFOS = (
    "gue.variant.reserved",
    "gue.variant.direct.bad_version",
    "gue.hlen.invalid",
    "gue.hlen.too_short",
    "gue.flags.unknown",
    "gue.priv_flags.unknown",
    "gue.exid.missing",
)

HEADER_FIELDS = ("gue.variant", "gue.control", "gue.hlen", "gue.proto", "gue.flags")


class TestBasicCapture:
    """ICMP echo over IPv4-in-GUE, plain header."""

    def test_every_frame_is_a_bare_variant_0_header(self, dissect):
        rows = dissect(BASIC, HEADER_FIELDS)
        assert len(rows) == 6
        # variant 0, data message, Hlen 0, proto 4 (IPIP), no flags
        assert rows == [["0", "0", "0", "4", "0x0000"]] * 6

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

    def test_protocol_chain(self, dissect):
        rows = dissect(BASIC, ("frame.protocols",))
        assert all(row == ["eth:ethertype:ip:udp:gue:ip:icmp:data"] for row in rows)


class TestRemcsumCapture:
    """UDP over IPv4-in-GUE with the private flags and remote checksum offload.

    Nothing is listening on the far side, so the odd frames are the requests
    carrying the extension and the even ones are ICMP port-unreachable replies
    coming back through the tunnel without it.
    """

    def test_requests_carry_private_flags_and_remcsum(self, dissect):
        rows = dissect(
            REMCSUM,
            (*HEADER_FIELDS, "gue.priv_flags", "gue.remcsum.start", "gue.remcsum.offset"),
            display_filter="gue.flags.priv == 1",
        )
        assert len(rows) == 3
        # Hlen 2 covers the private flags word plus the 4-byte remcsum field.
        # Checksum start 20 is the inner UDP header (right after a 20-byte IPv4
        # header) and offset 26 is its checksum field.
        assert rows == [["0", "0", "2", "4", "0x0001", "0x80000000", "20", "26"]] * 3

    def test_replies_carry_no_extension(self, dissect):
        rows = dissect(REMCSUM, HEADER_FIELDS, display_filter="gue.flags.priv == 0")
        assert rows == [["0", "0", "0", "4", "0x0000"]] * 3

    def test_inner_udp_is_dissected(self, dissect):
        rows = dissect(REMCSUM, ("frame.protocols",), display_filter="gue.flags.priv == 1")
        assert all(row == ["eth:ethertype:ip:udp:gue:ip:udp:data"] for row in rows)

    def test_surplus_space_is_not_reported(self, dissect):
        """Hlen 2 is fully consumed by the extension, so nothing is left over."""
        rows = dissect(REMCSUM, ("gue.surplus",), display_filter="gue.surplus")
        assert rows == []


@pytest.mark.parametrize("capture", [BASIC, REMCSUM])
class TestCaptureSanity:
    def test_six_frames_all_gue(self, dissect, capture):
        assert len(dissect(capture, ("frame.number",), display_filter="gue")) == 6

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
    def test_no_expert_info_fires(self, dissect, capture, expert):
        assert dissect(capture, ("frame.number",), display_filter=expert) == []
