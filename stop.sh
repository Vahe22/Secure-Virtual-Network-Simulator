#!/bin/bash
# Ջնջում ենք namespaces-երը, որոնք ստեղծվել են new.sh-ի կողմից
sudo ip netns del nsA 2>/dev/null
sudo ip netns del nsB 2>/dev/null
sudo ip netns del nsD1 2>/dev/null
sudo ip netns del nsD2 2>/dev/null
echo "Network cleaned up."
