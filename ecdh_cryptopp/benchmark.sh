#!/bin/bash

# This script will run ./rsa.o with various message size and various curve used
clear
echo Start Benchmarking...

# parameters
TEST=5
NUM=100
ENCRYPTION_ALG=ecdh
LIBRARY=cryptopp
PRG_CALL='./ecdh-agree.o'
ENV=$1

# output format
echo "$ENCRYPTION_ALG using $LIBRARY benchmark [average of $NUM encryptions]" > "$ENCRYPTION_ALG"_benchmarkTemp.txt
echo "Curve	Time for Secret Generation(us)" >> "$ENCRYPTION_ALG"_benchmarkTemp.txt

key_array=(secp160r1 secp224r1 secp256r1 secp384r1 secp521r1)

for (( i=0; i<$TEST; i++))
do
	
	msg_length=${msg_array[$i]}
	key=${key_array[$i]}
	echo "($(($i+1))/$TEST) Key Length: $key"

	echo -n "$key	" >> "$ENCRYPTION_ALG"_benchmarkTemp.txt

	total=$((0))
	l=$((msg_length / 2))
	#echo $l
	msg="$(openssl rand -hex $l)"
	#echo $msg
	#echo -n "$msg_length char	"
	for (( c=1; c<=$NUM; c++))
	do
		genTime="$($PRG_CALL $key)"
		#echo "$lastResult"
		totalGenTime=$(( totalGenTime + genTime ))
		
		echo -n .
	done
	echo

	averageGenTime=$((totalGenTime / NUM))
	echo "$averageGenTime" >> "$ENCRYPTION_ALG"_benchmarkTemp.txt
done

#Combine two file into one
mv "$ENCRYPTION_ALG"_benchmarkTemp.txt "$ENV"_"$ENCRYPTION_ALG"_"$LIBRARY"_benchmark.txt
echo
cat "$ENCRYPTION_ALG"_"$LIBRARY"_benchmark.txt
