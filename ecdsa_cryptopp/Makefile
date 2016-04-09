all: ecdsa arduino

ecdsa:
	g++ -g3 -ggdb -O0 -DDEBUG -Wall -Wextra cryptopp-test.cpp -o cryptopp-test.exe -lcryptopp -lpthread

arduino:
	g++ -g3 -ggdb -O0 -DDEBUG -Wall -Wextra ecdsa_with_arduino.cpp -o ecdsa_with_arduino.exe -lcryptopp -lpthread