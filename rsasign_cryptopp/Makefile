all: rsa

rsa:
	g++ -DDEBUG=1 -g3 -O0 -Wall -Wextra rsa.cpp -o rsa.o -lcryptopp

clean:
	rm *.o *.key *.txt

benchmark:
	./benchmark.sh