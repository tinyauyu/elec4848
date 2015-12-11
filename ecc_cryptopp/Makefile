all: ecc

ecc:
	g++ -DDEBUG=1 -g3 -O0 -Wall -Wextra ecc.cpp -o ecc.o -lcryptopp

clean:
	rm *.o *.key *.txt

benchmark:
	./benchmark.sh