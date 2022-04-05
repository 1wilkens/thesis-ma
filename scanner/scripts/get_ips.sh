#!/bin/sh

#awk '{print $2}' | tr . ' ' | awk '{print $1"."$2"."$3"."$4}' | uniq
tcpdump -tnr $1 | awk '{print $2}' | awk -F "." '{print $1"."$2"."$3"."$4}' | sort | uniq
