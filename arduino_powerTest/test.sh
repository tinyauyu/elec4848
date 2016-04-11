#!/bin/bash
i=0  # select group here

PRG_CALL='../rsa_cryptopp/rsa.o'

msg_array=(80 112 128 192 256)
key_array=(1024 2048 3072 7680 15360)

msg_length=${msg_array[$i]}
key=${key_array[$i]}

l=$((msg_length / 2))
msg="$(openssl rand -hex $l)"

sudo ./on.sh 21
../rsa_cryptopp/rsa.o 
"$($PRG_CALL $key $msg)"
sudo ./off.sh 21