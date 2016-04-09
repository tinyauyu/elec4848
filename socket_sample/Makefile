all: client server

client:
	g++ -g3 -ggdb -O0 -DDEBUG -Wall -Wextra client.cpp -o client.exe -lcryptopp -lpthread

server:
	g++ -g3 -ggdb -O0 -DDEBUG -Wall -Wextra server.cpp -o server.exe -lcryptopp -lpthread

clean:
	rm *.o *.pem *.txt