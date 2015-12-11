all: rsa

rsa:
	gcc rsa.c -o rsa.o -lcrypto

clean:
	rm *.o *.pem *.txt

benchmark:
	./benchmark.sh