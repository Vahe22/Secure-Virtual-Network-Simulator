#!/usr/bin/env bash
set -euo pipefail

# Direct SafeChannel-1G topology with 1 Gbit/s shaping on the middle link.
#
# Topology:
#   nsA:vA <-> nsD1:vD1L   [dev1]   nsD1:vD1R <-> nsD2:vD2L   [dev2]   nsD2:vD2R <-> nsB:vB
#
# Adds tc shaping to emulate a 1 Gbit/s "virtual cable" between dev1 and dev2.
# You can tweak RATE / DELAY / BURST below.

RATE="1gbit"
DELAY="100us"
BURST="64kb"
LATENCY="50ms"

for ns in nsA nsD1 nsD2 nsB; do
  ip netns del "$ns" 2>/dev/null || true
done

ip netns add nsA
ip netns add nsD1
ip netns add nsD2
ip netns add nsB

# A <-> D1 left
ip link add vA type veth peer name vD1L
ip link set vA   netns nsA
ip link set vD1L netns nsD1

# D1 right <-> D2 left (direct link)
ip link add vD1R type veth peer name vD2L
ip link set vD1R netns nsD1
ip link set vD2L netns nsD2

# D2 right <-> B
ip link add vD2R type veth peer name vB
ip link set vD2R netns nsD2
ip link set vB   netns nsB

# IPs only at the edges
ip -n nsA addr add 10.20.20.1/24 dev vA
ip -n nsB addr add 10.20.20.2/24 dev vB

# Bring up loopbacks
for ns in nsA nsD1 nsD2 nsB; do
  ip -n "$ns" link set lo up
done

# Bring up all interfaces
ip -n nsA  link set vA up

ip -n nsD1 link set vD1L up
ip -n nsD1 link set vD1R up

ip -n nsD2 link set vD2L up
ip -n nsD2 link set vD2R up

ip -n nsB  link set vB up

# Shape the middle link both directions.
# nsD1:vD1R egress limits traffic D1 -> D2
ip netns exec nsD1 tc qdisc replace dev vD1R root handle 1: tbf rate "$RATE" burst "$BURST" latency "$LATENCY"
ip netns exec nsD1 tc qdisc add dev vD1R parent 1:1 handle 10: netem delay "$DELAY"

# nsD2:vD2L egress limits traffic D2 -> D1
ip netns exec nsD2 tc qdisc replace dev vD2L root handle 1: tbf rate "$RATE" burst "$BURST" latency "$LATENCY"
ip netns exec nsD2 tc qdisc add dev vD2L parent 1:1 handle 10: netem delay "$DELAY"

echo "[OK] direct topology with 1 Gbit/s shaping is up"
echo
echo "Shaping parameters:"
echo "  RATE    = $RATE"
echo "  DELAY   = $DELAY"
echo "  BURST   = $BURST"
echo "  LATENCY = $LATENCY"
echo
echo "Interfaces:"
echo "  nsA : vA"
echo "  nsD1: vD1L vD1R"
echo "  nsD2: vD2L vD2R"
echo "  nsB : vB"
echo
echo "Verify tc:"
echo "  sudo ip netns exec nsD1 tc qdisc show dev vD1R"
echo "  sudo ip netns exec nsD2 tc qdisc show dev vD2L"
echo
echo "Build:"
echo "  gcc -O2 -Wall -Wextra -DROLE=1 -o dev1_bin dev_common.c -lcrypto"
echo "  gcc -O2 -Wall -Wextra -DROLE=2 -o dev2_bin dev_common.c -lcrypto"
echo "  gcc -O2 -Wall -Wextra -o sender sender.c"
echo "  gcc -O2 -Wall -Wextra -o receiver receiver.c"
echo
echo "Run order:"
echo "  sudo ip netns exec nsB  ./receiver 40000 out/received.bin"
echo "  sudo ip netns exec nsD1 ./dev1_bin"
echo "  sudo ip netns exec nsD2 ./dev2_bin"
echo "  sudo ip netns exec nsA  ./sender 10.20.20.2 40000 1g.bin"
echo
echo "Remove shaping only:"
echo "  sudo ip netns exec nsD1 tc qdisc del dev vD1R root"
echo "  sudo ip netns exec nsD2 tc qdisc del dev vD2L root"


# Ակտիվացնել IP Forwarding (սա պետք է, որ թրաֆիկը անցնի D1-ով և D2-ով)
ip netns exec nsD1 sysctl -w net.ipv4.ip_forward=1
ip netns exec nsD2 sysctl -w net.ipv4.ip_forward=1

echo "Network Infrastructure is ready."
