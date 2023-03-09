#!/bin/bash
vtysh -c 'conf t' \
-c 'segment-routing' \
-c ' traffic-eng' \
-c '  pcep' \
-c '   pce POLA' \
-c '    address ip 10.0.255.254' \
-c '    source-address ip 10.0.255.3' \
-c '    pce-initiated' \
-c '   exit' \
-c '   pcc' \
-c '    peer POLA' \
-c '   exit' \
-c '  exit' \
-c ' exit' \
-c 'exit' \
> /dev/null 2>&1
