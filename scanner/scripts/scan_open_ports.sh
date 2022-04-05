#!/bin/bash

ports=(80 444 448 843 943 1443 8080 8000 8888)

zmap_cmd="zmap -q -B 150M -i eth1 -p <PORT> -w data/ripe_ipv4_cidr.txt -o data/zmap_ripe_<PORT>.csv"

if [ $(whoami) != 'root' ]; then
	echo "Must be root to run $0"
	exit 1;
fi

for p in ${ports[@]}; do
	cmd=${zmap_cmd//<PORT>/$p}
	echo "Scanning port: $p"
	$cmd
done
