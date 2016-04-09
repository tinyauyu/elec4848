all: ecdh

ecdh:
	g++ -DDEBUG=1 -g3 -O0 -Wall -Wextra ecdh-agree.cpp -o ecdh-agree.o -lcryptopp

clean:
	rm *.o *.key *.txt

benchmark:
	./benchmark.sh