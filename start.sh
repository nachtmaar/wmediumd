#!/usr/bin/env bash

hwaddr=$(ifconfig wlan0|grep HWaddr|awk '{print $5}')

cat << EOF > single_node.cfg
ifaces: { count = 1; ids = ["$hwaddr"]; }
EOF

wmediumd/wmediumd -c single_node.cfg 2>&1 > wmediumd.log &
