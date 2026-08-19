--
-- gue.lua - Generic UDP Encapsulation (GUE) dissector
--
-- draft-ietf-intarea-gue-09, plus the flags the Linux kernel actually
-- puts on the wire (include/net/gue.h, net/ipv4/fou.c).
--
-- Copyright 2026, Yuya Kusakabe <yuya.kusakabe@gmail.com>
--
-- Install by copying this file into the personal plugin directory shown by
-- Help -> About Wireshark -> Folders, e.g.
--     ~/.local/lib/wireshark/plugins/
-- or load it for a single run with
--     tshark -X lua_script:gue.lua -r capture.pcap
--
-- SPDX-License-Identifier: GPL-2.0-or-later
--

local DEFAULT_UDP_PORT = 6080 -- IANA "gue"

-- Linux include/net/gue.h
local GUE_FLAG_PRIV = 0x0001 -- private flags are in the options
local GUE_LEN_PRIV = 4
local GUE_PFLAG_REMCSUM = 0x80000000 -- remote checksum offload
local GUE_PLEN_REMCSUM = 4

local GUE_CTYPE_EXPERIMENT = 255
local GUE_EXID_LEN = 4

local IP_PROTO_IPV6_NONXT = 59 -- "no next header"

local gue = Proto("gue", "Generic UDP Encapsulation")

local variant_names = {
    [0] = "GUE header",
    [1] = "Direct IP encapsulation",
    [2] = "Reserved",
    [3] = "Reserved",
}

-- draft-ietf-intarea-gue-09 section 3.2.2: 0 and 255 are defined, the rest
-- is reserved.  Spelled out so every value gets a label.
local ctype_names = {
    [0] = "Needs more context for interpretation",
    [GUE_CTYPE_EXPERIMENT] = "Experimental",
}
for i = 1, 254 do
    ctype_names[i] = "Reserved"
end

-- The IP protocol numbers that turn up inside GUE.  Anything else is shown
-- as a bare number.
local ip_proto_names = {
    [1] = "ICMP",
    [4] = "IPv4",
    [6] = "TCP",
    [17] = "UDP",
    [41] = "IPv6",
    [47] = "GRE",
    [58] = "IPv6-ICMP",
    [59] = "IPv6-NoNxt",
    [97] = "ETHERIP",
}

local pf = {
    variant = ProtoField.uint8("gue.variant", "Variant", base.DEC, variant_names, 0xC0),
    control = ProtoField.bool(
        "gue.control",
        "Message type",
        8,
        { "Control message", "Data message" },
        0x20
    ),
    hlen = ProtoField.uint8(
        "gue.hlen",
        "Header length",
        base.DEC,
        nil,
        0x1F,
        "Header length in 32-bit words, excluding the first four bytes"
    ),
    proto = ProtoField.uint8(
        "gue.proto",
        "Proto",
        base.DEC,
        ip_proto_names,
        0,
        "IP protocol of the encapsulated packet"
    ),
    ctype = ProtoField.uint8("gue.ctype", "Control type", base.DEC, ctype_names, 0),
    flags = ProtoField.uint16("gue.flags", "Flags", base.HEX),
    flags_priv = ProtoField.bool(
        "gue.flags.priv",
        "Private flags present",
        16,
        nil,
        GUE_FLAG_PRIV
    ),
    flags_reserved = ProtoField.uint16(
        "gue.flags.reserved",
        "Reserved",
        base.HEX,
        nil,
        0xFFFE
    ),
    priv_flags = ProtoField.uint32("gue.priv_flags", "Private flags", base.HEX),
    priv_remcsum = ProtoField.bool(
        "gue.priv_flags.remcsum",
        "Remote checksum offload",
        32,
        nil,
        GUE_PFLAG_REMCSUM
    ),
    priv_reserved = ProtoField.uint32(
        "gue.priv_flags.reserved",
        "Reserved",
        base.HEX,
        nil,
        0x7FFFFFFF
    ),
    remcsum_start = ProtoField.uint16(
        "gue.remcsum.start",
        "Checksum start",
        base.DEC,
        nil,
        0,
        "Offset of the checksum computation start within the encapsulated packet"
    ),
    remcsum_offset = ProtoField.uint16(
        "gue.remcsum.offset",
        "Checksum offset",
        base.DEC,
        nil,
        0,
        "Offset of the checksum field within the encapsulated packet"
    ),
    ext_fields = ProtoField.bytes("gue.ext_fields", "Extension fields"),
    surplus = ProtoField.bytes("gue.surplus", "Surplus space"),
    exid = ProtoField.uint32("gue.exid", "Experimental identifier", base.HEX),
    control_payload = ProtoField.bytes("gue.control_payload", "Control message"),
}

gue.fields = {
    pf.variant,
    pf.control,
    pf.hlen,
    pf.proto,
    pf.ctype,
    pf.flags,
    pf.flags_priv,
    pf.flags_reserved,
    pf.priv_flags,
    pf.priv_remcsum,
    pf.priv_reserved,
    pf.remcsum_start,
    pf.remcsum_offset,
    pf.ext_fields,
    pf.surplus,
    pf.exid,
    pf.control_payload,
}

local ef_variant_reserved = ProtoExpert.new(
    "gue.variant.reserved",
    "Reserved GUE variant",
    expert.group.PROTOCOL,
    expert.severity.WARN
)
local ef_direct_bad_version = ProtoExpert.new(
    "gue.variant.direct.bad_version",
    "Variant 1 payload is neither IPv4 nor IPv6",
    expert.group.PROTOCOL,
    expert.severity.WARN
)
local ef_hlen_invalid = ProtoExpert.new(
    "gue.hlen.invalid",
    "Header length goes past the end of the packet",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local ef_hlen_too_short = ProtoExpert.new(
    "gue.hlen.too_short",
    "Header length too short for the extension fields the flags call for",
    expert.group.MALFORMED,
    expert.severity.ERROR
)
local ef_flags_unknown = ProtoExpert.new(
    "gue.flags.unknown",
    "Unknown flag set",
    expert.group.PROTOCOL,
    expert.severity.WARN
)
local ef_priv_flags_unknown = ProtoExpert.new(
    "gue.priv_flags.unknown",
    "Unknown private flag set",
    expert.group.PROTOCOL,
    expert.severity.WARN
)
local ef_exid_missing = ProtoExpert.new(
    "gue.exid.missing",
    "Control type 255 requires a 4-byte experimental identifier",
    expert.group.MALFORMED,
    expert.severity.ERROR
)

gue.experts = {
    ef_variant_reserved,
    ef_direct_bad_version,
    ef_hlen_invalid,
    ef_hlen_too_short,
    ef_flags_unknown,
    ef_priv_flags_unknown,
    ef_exid_missing,
}

gue.prefs.udp_port =
    Pref.uint("UDP port", DEFAULT_UDP_PORT, "UDP port GUE is carried on")

local ip_proto_table, ip_dissector, ipv6_dissector, data_dissector

--
-- Variant 1 has no GUE header: the first two bits of the IP version field
-- double as the variant number, so the UDP payload is simply an IP packet.
--
local function dissect_variant_direct(tvbuf, pinfo, root, first_byte)
    local ti = root:add(gue, tvbuf:range(0, 1))
    ti:append_text(", Direct IP encapsulation")
    local variant_ti = ti:add(pf.variant, tvbuf:range(0, 1))

    local ip_version = math.floor(first_byte / 16)
    if ip_version == 4 then
        ip_dissector:call(tvbuf, pinfo, root)
    elseif ip_version == 6 then
        ipv6_dissector:call(tvbuf, pinfo, root)
    else
        variant_ti:add_proto_expert_info(ef_direct_bad_version)
        data_dissector:call(tvbuf, pinfo, root)
    end
end

function gue.dissector(tvbuf, pinfo, root)
    local pktlen = tvbuf:reported_length_remaining()
    if pktlen < 1 then
        return 0
    end

    pinfo.cols.protocol:set("GUE")

    local first_byte = tvbuf:range(0, 1):uint()
    local variant = math.floor(first_byte / 64)

    if variant == 1 then
        dissect_variant_direct(tvbuf, pinfo, root, first_byte)
        return pktlen
    end

    if variant ~= 0 then
        local ti = root:add(gue, tvbuf:range(0))
        ti:add(pf.variant, tvbuf:range(0, 1)):add_proto_expert_info(ef_variant_reserved)
        data_dissector:call(tvbuf, pinfo, root)
        return pktlen
    end

    local control = (first_byte % 64) >= 32
    local hlen = first_byte % 32

    -- Hlen counts 32-bit words after the first four bytes, not including them.
    local opt_len = 4 * hlen
    local hdr_len = 4 + opt_len
    local hlen_valid = hdr_len <= pktlen

    -- A control message has no next dissector, so GUE owns the whole payload;
    -- a data message owns only its header.
    local ti
    if control or not hlen_valid then
        ti = root:add(gue, tvbuf:range(0))
    else
        ti = root:add(gue, tvbuf:range(0, hdr_len))
    end

    ti:add(pf.variant, tvbuf:range(0, 1))
    ti:add(pf.control, tvbuf:range(0, 1))
    local hlen_ti = ti:add(pf.hlen, tvbuf:range(0, 1))
    hlen_ti:append_text(string.format(" (%d bytes)", hdr_len))

    -- hdr_len is at least 4, so a shorter packet is already the "header runs
    -- past the end" case.
    if pktlen < 4 then
        hlen_ti:add_proto_expert_info(ef_hlen_invalid)
        return pktlen
    end

    local proto_ctype = tvbuf:range(1, 1):uint()
    ti:add(control and pf.ctype or pf.proto, tvbuf:range(1, 1))

    local flags = tvbuf:range(2, 2):uint()
    local flags_ti = ti:add(pf.flags, tvbuf:range(2, 2))
    flags_ti:add(pf.flags_reserved, tvbuf:range(2, 2))
    flags_ti:add(pf.flags_priv, tvbuf:range(2, 2))

    if not hlen_valid then
        hlen_ti:add_proto_expert_info(ef_hlen_invalid)
        if pktlen > 4 then
            data_dissector:call(tvbuf:range(4):tvb(), pinfo, root)
        end
        return pktlen
    end

    local opt_used = 0
    if flags - (flags % 2) ~= 0 then
        -- Extension fields are laid out in flag order, so a single
        -- unrecognised flag makes every offset indeterminate (section 3.3.1).
        flags_ti:add_proto_expert_info(ef_flags_unknown)
        if opt_len > 0 then
            ti:add(pf.ext_fields, tvbuf:range(4, opt_len))
        end
        opt_used = opt_len
    elseif flags % 2 == 1 then
        if opt_len < GUE_LEN_PRIV then
            hlen_ti:add_proto_expert_info(ef_hlen_too_short)
        else
            local pflags = tvbuf:range(4, 4):uint()
            local pflags_ti = ti:add(pf.priv_flags, tvbuf:range(4, 4))
            pflags_ti:add(pf.priv_remcsum, tvbuf:range(4, 4))
            pflags_ti:add(pf.priv_reserved, tvbuf:range(4, 4))
            opt_used = GUE_LEN_PRIV

            if pflags % GUE_PFLAG_REMCSUM ~= 0 then
                -- Same indeterminacy as above, one level down.
                pflags_ti:add_proto_expert_info(ef_priv_flags_unknown)
                if opt_len > opt_used then
                    ti:add(pf.ext_fields, tvbuf:range(4 + opt_used, opt_len - opt_used))
                end
                opt_used = opt_len
            elseif pflags >= GUE_PFLAG_REMCSUM then
                if opt_len < opt_used + GUE_PLEN_REMCSUM then
                    hlen_ti:add_proto_expert_info(ef_hlen_too_short)
                else
                    ti:add(pf.remcsum_start, tvbuf:range(4 + opt_used, 2))
                    ti:add(pf.remcsum_offset, tvbuf:range(4 + opt_used + 2, 2))
                    opt_used = opt_used + GUE_PLEN_REMCSUM
                end
            end
        end
    end

    -- Surplus space is reserved and must not be interpreted (section 3.4).
    if opt_len > opt_used then
        ti:add(pf.surplus, tvbuf:range(4 + opt_used, opt_len - opt_used))
    end

    local remaining = pktlen - hdr_len

    if control then
        pinfo.cols.info:set(
            string.format(
                "GUE control message, type %d (%s)",
                proto_ctype,
                ctype_names[proto_ctype] or "Unknown"
            )
        )
        local control_offset = 0
        if proto_ctype == GUE_CTYPE_EXPERIMENT then
            -- The ExID lives in the payload, so Hlen does not account for it.
            if remaining < GUE_EXID_LEN then
                ti:add_proto_expert_info(ef_exid_missing)
            else
                ti:add(pf.exid, tvbuf:range(hdr_len, GUE_EXID_LEN))
                control_offset = GUE_EXID_LEN
            end
        end
        -- An experimental control message may consist of nothing but the ExID.
        if remaining - control_offset > 0 then
            ti:add(pf.control_payload, tvbuf:range(hdr_len + control_offset))
        end
        return pktlen
    end

    if remaining <= 0 then
        return pktlen
    end

    local next_tvb = tvbuf:range(hdr_len):tvb()
    -- Protocol 59 says the payload does not begin with an IP protocol header,
    -- so it must not be parsed as one (section 3.2.1).
    local sub = nil
    if proto_ctype ~= IP_PROTO_IPV6_NONXT then
        sub = ip_proto_table:get_dissector(proto_ctype)
    end
    if sub ~= nil then
        sub:call(next_tvb, pinfo, root)
    else
        data_dissector:call(next_tvb, pinfo, root)
    end

    return pktlen
end

local registered_port

local function register_port()
    local udp_port_table = DissectorTable.get("udp.port")
    if registered_port ~= nil then
        udp_port_table:remove(registered_port, gue)
    end
    registered_port = gue.prefs.udp_port
    udp_port_table:add(registered_port, gue)
end

function gue.init()
    ip_proto_table = DissectorTable.get("ip.proto")
    ip_dissector = Dissector.get("ip")
    ipv6_dissector = Dissector.get("ipv6")
    data_dissector = Dissector.get("data")
end

function gue.prefs_changed()
    if gue.prefs.udp_port ~= registered_port then
        register_port()
    end
end

register_port()
