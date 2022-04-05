#!/bin/sh

sudo tcpdump -Q in -i eth1 -F td_filter.txt -w $1

