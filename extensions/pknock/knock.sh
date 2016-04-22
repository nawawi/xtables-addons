#!/bin/bash
# $1 -> IP src
# $2 -> IP dst
# $3 -> PORT dst
# $4 -> secret

if [ -z $4 ]; then 
    echo "usage: $0 <IP src> <IP dst> <PORT dst> <secret>"
    exit 1
fi

digest_file="/tmp/digest.txt"

python ../test/py/gen_hmac.py $4 $1 > $digest_file
nemesis udp -S $1 -D $2 -y $3 -P $digest_file
