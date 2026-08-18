#!/bin/bash
#
# Capture real Linux GUE traffic in an isolated pair of network namespaces.
# Everything is torn down on exit, so the host network is left untouched.
#
# Usage:
#   sudo ./capture-gue.sh out.pcap              # plain GUE header (Hlen 0)
#   sudo ./capture-gue.sh out.pcap --remcsum    # + private flags and REMCSUM
#
# Remote checksum offload only kicks in when the inner packet needs a
# checksum offloaded, so the --remcsum mode sends UDP rather than ICMP.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
set -e

OUT="${1:?usage: $0 <output.pcap> [--remcsum]}"
MODE="${2:-}"

ENCAP_OPTS=""
if [ "$MODE" = "--remcsum" ]; then
    ENCAP_OPTS="encap-remcsum"
fi

cleanup() {
    ip netns del gue-a 2>/dev/null || true
    ip netns del gue-b 2>/dev/null || true
}
trap cleanup EXIT
cleanup

modprobe fou
modprobe ipip

ip netns add gue-a
ip netns add gue-b
ip link add veth-a type veth peer name veth-b
ip link set veth-a netns gue-a
ip link set veth-b netns gue-b

ip netns exec gue-a ip addr add 198.51.100.1/24 dev veth-a
ip netns exec gue-a ip link set veth-a up
ip netns exec gue-a ip link set lo up
ip netns exec gue-b ip addr add 198.51.100.2/24 dev veth-b
ip netns exec gue-b ip link set veth-b up
ip netns exec gue-b ip link set lo up

# GUE receive ports on the IANA-assigned port
ip netns exec gue-a ip fou add port 6080 gue
ip netns exec gue-b ip fou add port 6080 gue

# IPv4-in-GUE (proto 4)
ip netns exec gue-a ip link add name gue4 type ipip \
    remote 198.51.100.2 local 198.51.100.1 \
    encap gue encap-sport 6080 encap-dport 6080 $ENCAP_OPTS
ip netns exec gue-a ip addr add 10.0.0.1/24 dev gue4
ip netns exec gue-a ip link set gue4 up

ip netns exec gue-b ip link add name gue4 type ipip \
    remote 198.51.100.1 local 198.51.100.2 \
    encap gue encap-sport 6080 encap-dport 6080 $ENCAP_OPTS
ip netns exec gue-b ip addr add 10.0.0.2/24 dev gue4
ip netns exec gue-b ip link set gue4 up

ip netns exec gue-a tcpdump -i veth-a -w "$OUT" -U udp port 6080 &
TCPDUMP_PID=$!
sleep 1

if [ "$MODE" = "--remcsum" ]; then
    ip netns exec gue-a bash -c \
        'for i in 1 2 3; do echo payloadtest > /dev/udp/10.0.0.2/9999; sleep 0.2; done' || true
else
    ip netns exec gue-a ping -c 3 -i 0.3 -s 16 10.0.0.2 >/dev/null || true
fi

sleep 1
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

chmod 644 "$OUT"
echo "wrote $OUT"
