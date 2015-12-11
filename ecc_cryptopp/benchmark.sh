#!/bin/bash

# This script will run ./rsa.o with various message size and various curve used
clear
echo Start Benchmarking...

# parameters
TEST=5
NUM=100
ENCRYPTION_ALG=ecc
LIBRARY=cryptopp
PRG_CALL='./ecc.o'

# output format
echo "$ENCRYPTION_ALG using $LIBRARY benchmark [average of $NUM encryptions]" > "$ENCRYPTION_ALG"_benchmarkTemp.txt
echo "Curve	Encryption Time(us)	Decryption Time(us)" >> "$ENCRYPTION_ALG"_benchmarkTemp.txt

msg_array=(80 112 128 192 256)
key_array=(secp160r1 secp224r1 secp256r1 secp384r1 secp521r1)

for (( i=0; i<$TEST; i++))
do
	
	msg_length=${msg_array[$i]}
	key=${key_array[$i]}
	echo "($(($i+1))/$TEST) Key Length: $key		Message Length: $msg_length"

	echo -n "$key	" >> "$ENCRYPTION_ALG"_benchmarkTemp.txt
	echo -n "$key	" >> "$ENCRYPTION_ALG"_decryptionTime.txt

	total=$((0))
	l=$((msg_length / 2))
	#echo $l
	msg="$(openssl rand -hex $l)"
	#echo $msg
	#echo -n "$msg_length char	"
	for (( c=1; c<=$NUM; c++))
	do
		lastResult="$($PRG_CALL $key $msg)"
		#echo "$lastResult"
		t="encryption"
		for time in $lastResult
		do
			if [ "$t" = "encryption" ]
			then
				#echo encryption
				encryptionTime=$time
				t="decryption"
			else
				#echo decryption
				decryptionTime=$time
			fi
		done
		totalEncryption=$(( totalEncryption + encryptionTime ))
		totalDecryption=$(( totalDecryption + decryptionTime ))
		
		echo -n .
	done
	echo

	averageEncryption=$((totalEncryption / NUM))
	averageDecryption=$((totalDecryption / NUM))
	echo -n "$averageEncryption	" >> "$ENCRYPTION_ALG"_benchmarkTemp.txt
	echo "$averageDecryption" >> "$ENCRYPTION_ALG"_benchmarkTemp.txt
done

#Combine two file into one
mv "$ENCRYPTION_ALG"_benchmarkTemp.txt "$ENCRYPTION_ALG"_"$LIBRARY"_benchmark.txt
echo
cat "$ENCRYPTION_ALG"_"$LIBRARY"_benchmark.txt