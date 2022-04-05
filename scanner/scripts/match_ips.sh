#!/bin/bash

fscanner=$1
ftcpdump=$2

echo "Matching ips from $fscanner and $ftcpdump"

IFS=$'\r\n'
GLOBIGNORE='*'

iscanner=($(cat $fscanner))
itcpdump=($(cat $ftcpdump))
count=0
for i in ${!itcpdump[@]}; do
    for j in ${!iscanner[@]}; do
        if [ ${itcpdump[i]} == ${iscanner[j]} ]; then
            count=$((count+1))
            echo "Match #$count: ${iscanner[j]}"
        fi
    done

    if [ $count -eq ${#iscanner[@]} ]; then
        break;
    fi
done
