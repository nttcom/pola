#!/bin/bash
# "vtysh -b" cannot enter the segment-routing node, so the PCEP session is configured here
# instead of in frr.conf.
vtysh -c 'conf t' \
-c 'segment-routing' \
-c ' traffic-eng' \
-c '  pcep' \
-c '   pce POLA' \
-c '    address ip 10.0.255.254' \
-c '    source-address ip 10.0.255.1' \
-c '    pce-initiated' \
-c '   exit' \
-c '   pcc' \
-c '    peer POLA'

# FRR overwrites the RD and export RT of frr.conf when the cust-a VRF appears.
vtysh -c 'conf t' \
-c 'router bgp 65000 vrf cust-a' \
-c ' address-family ipv4 unicast' \
-c '  rd vpn export 65000:10' \
-c '  rt vpn both 65000:10'
