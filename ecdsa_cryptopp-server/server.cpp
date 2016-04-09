/*
** echo_server.c -- Demo program: echo server
**
** Author: atctam
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>   /* for perror() */
/* for using socket functions */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#define MYPORT 49952    // the server port number
                  // it must be unique within the server host machine
                  // you can change this number to a port number 
                  // within your allocated range

#define BACKLOG 10     // how many pending connections queue will hold

#define MAXDATASIZE 128 // max number of bytes we can get at once 

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDSA;

#include "cryptopp/sha.h"
using CryptoPP::SHA1;
using CryptoPP::SHA256;

#include "cryptopp/queue.h"
using CryptoPP::ByteQueue;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>
CryptoPP::OID curve(string c){
    int curveNum = 11;
    CryptoPP::OID curves[] = {
        secp160k1(),
        secp160r1(),
        secp160r2(),
        secp192k1(),
        secp192r1(),
        secp224k1(),
        secp224r1(),
        secp256k1(),
        secp256r1(),
        secp384r1(),
        secp521r1()
    };
    string curves_name[] = {
        "secp160k1",
        "secp160r1",
        "secp160r2",
        "secp192k1",
        "secp192r1",
        "secp224k1",
        "secp224r1",
        "secp256k1",
        "secp256r1",
        "secp384r1",
        "secp521r1"
    };
    for(int i=0; i<curveNum; i++){
        if(c.compare(curves_name[i])==0){
            return curves[i];
        }
    }
    cout << "Curve: '"<< c <<"' not found!\n";
    exit(-1);
}

struct package {
  string curve;
  string pub_key;
  string message;
  string signature;
};


int main(void)
{
    int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
    struct sockaddr_in my_addr;    // my address information
    struct sockaddr_in peer_addr;  // client's address information
    socklen_t sin_size;
    struct package incoming;
    ByteQueue privateKey, publicKey;
    char buf[MAXDATASIZE];

   /* Create the socket for TCP communication */
   /* For the exercise, change this part to use UDP */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

   /* Prepare the socket address structure of the server 
   */    
    my_addr.sin_family = AF_INET;         // host byte order
    my_addr.sin_port = htons(MYPORT);     // short, network byte order
    my_addr.sin_addr.s_addr = htonl(INADDR_ANY); // automatically fill with my IP address
    memset(&(my_addr.sin_zero), '\0', 8); // zero the rest of the struct

   /* Associate my address info to the socket */
    if (bind(sockfd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr)) == -1) {
        perror("bind");
        exit(1);
    }

   /* Set up the listen queue for TCP server socket */
   /* For the exercise, you can comment out (remove) this part */
    if (listen(sockfd, BACKLOG) == -1) {
        perror("listen");
        exit(1);
    }

   /* For TCP server socket, block waiting for incoming connection */
   /* For the exercise, you can comment out (or remove) this part */
   {
      sin_size = sizeof(struct sockaddr_in);
      if ((new_fd = accept(sockfd, (struct sockaddr *)&peer_addr, &sin_size)) == -1) {
         perror("accept");
         exit(1);
      }
      printf("server: got connection from %s\n",inet_ntoa(peer_addr.sin_addr));
   }
   
   /* Stage 1: Handshaking */
    if ((numbytes=recv(new_fd, &incoming, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    } else if (numbytes > 0) {

      incoming.pub_key[numbytes-9]='\0';
      cout << "Curve: " << incoming.curve << endl;
      cout << "Public Key (base64): " << incoming.pub_key << endl;

      // Construct the Public Key
      HexDecoder decoder;
      decoder.Put((byte*)incoming.pub_key.data(), incoming.pub_key.size());
      decoder.MessageEnd();

      ECP::Point q;
      size_t len = decoder.MaxRetrievable();
      assert(len == SHA256::DIGESTSIZE * 2);

      q.identity = false;
      q.x.Decode(decoder, len/2);
      q.y.Decode(decoder, len/2);

      ECDSA<ECP, SHA256>::PublicKey pubKey;
      pubKey.Initialize( curve(incoming.curve), q );
      pubKey.Save( publicKey );
        
      /* ack */
      string ok = "ok"
      if (send(new_fd, ok.c_str, numbytes, 0) == -1)
          perror("send");
    }

    /* Stage 2: receive message */
    if ((numbytes=recv(new_fd, &buf, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    } else if (numbytes > 0) {
      message = buf;

        /* ack */
      string ok = "ok"
      if (send(new_fd, ok.c_str, numbytes, 0) == -1)
          perror("send");
    }

    /* Stage 3: receive signature */
    if ((numbytes=recv(new_fd, &buf, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    } else if (numbytes > 0) {
      signature = buf;

        /* ack */
      string ok = "ok"
      if (send(new_fd, ok.c_str, numbytes, 0) == -1)
          perror("send");
    }



   /* For the exercise, add the code for communication using UDP in here */
   /* First, add a recvfrom() statement to get the message as well as 
      the client's address info */
   /* Second, add two printf() statements to print out client info and 
      the message */
   /* Third, add a sendto() statement to send back the message to the
      client process */
      
      
   /* close the sockets */
    close(new_fd);   // remove this one for the exercise
   close(sockfd);
   
   /* For the exercise, you can comment out (or remove) this part */
    printf("Close connection.\n\n");
   /* For the exercise, uncomment this part */
   /* printf("Finished\n"); */


    return 0;
}

