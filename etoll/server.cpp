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
#include <string.h>
/* for using socket functions */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

/* for encryption functions */
#include <iostream>
using std::ostream;
using std::cout;
using std::endl;

#include <fstream>
using std::ofstream;
using std::ifstream;

#include <string>
using std::string;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptopp/hex.h>
using CryptoPP::HexEncoder;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/integer.h>
using CryptoPP::Integer;

#include <cryptopp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

#include <cryptopp/eccrypto.h>
using CryptoPP::ECDSA;
using CryptoPP::ECP;    // Prime field
using CryptoPP::EC2N;   // Binary field
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptopp/pubkey.h>
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;

#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
namespace ASN1 = CryptoPP::ASN1;

#include <cryptopp/cryptlib.h>
using CryptoPP::PK_Encryptor;
using CryptoPP::PK_Decryptor;
using CryptoPP::g_nullNameValuePairs;


#include <iomanip> // This might be necessary

#include <stdexcept>
using std::runtime_error;

#include <cstdlib>
using std::exit;

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

#include <map>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sstream>
using std::stringstream;

#include "base64.h"
#include "base64.cpp"


#define MYPORT 49950    // the server port number
                  // it must be unique within the server host machine
                  // you can change this number to a port number 
                  // within your allocated range

#define BACKLOG 10     // how many pending connections queue will hold

#define MAXDATASIZE 10000 // max number of bytes we can get at once 

CryptoPP::OID curve(string c){
    int curveNum = 11;
    CryptoPP::OID curves[] = {
        ASN1::secp160k1(),
        ASN1::secp160r1(),
        ASN1::secp160r2(),
        ASN1::secp192k1(),
        ASN1::secp192r1(),
        ASN1::secp224k1(),
        ASN1::secp224r1(),
        ASN1::secp256k1(),
        ASN1::secp256r1(),
        ASN1::secp384r1(),
        ASN1::secp521r1()
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

inline bool isExist (const std::string& name) {
    return ( access( name.c_str(), F_OK ) != -1 );
}

void LoadPrivateKey(PrivateKey& key, const string& file = "ecies.private.key");
void LoadPublicKey(PublicKey& key, const string& file = "ecies.public.key");
void SavePrivateKey(const PrivateKey& key, string& s);
void SavePublicKey(const PublicKey& key, string& s);

int main(void)
{
    int sockfd, new_fd, numbytes;  // listen on sock_fd, new connection on new_fd
    struct sockaddr_in my_addr;    // my address information
    struct sockaddr_in peer_addr;  // client's address information
    socklen_t sin_size;
    char curveName[10];
    char c_encoded[MAXDATASIZE];

    AutoSeededRandomPool prng;
    ECIES<ECP>::Encryptor e0;
    ECIES<ECP>::Decryptor d0;
    ECDSA<ECP, SHA256>::PrivateKey ecdsa_privateKey;

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

   /* Listen to client for curveName*/
   if ((numbytes=recv(new_fd, curveName, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    } else if (numbytes > 0) {
   /* if client side's connection is closed with bruteforce, recv() will return '0'
   */
      curveName[numbytes]='\0';
      printf("\tReceived: %s\n", curveName);

      string ecies_privateKeyFileName = "ecc-private-";
      ecies_privateKeyFileName.append(curveName);
      ecies_privateKeyFileName.append(".key");
      string ecies_publicKeyFileName = "ecc-public-";
      ecies_publicKeyFileName.append(curveName);
      ecies_publicKeyFileName.append(".key");

      stringstream ecdsa_privateKeyFileName, ecdsa_publicKeyFileName;
      ecdsa_privateKeyFileName << "ecdsa-private-" << curveName << ".key";
      ecdsa_publicKeyFileName << "ecdsa-public-" << curveName << ".key";

      stringstream signatureFileName;
      signatureFileName << "signature-" << curveName << ".sign";


      /* Generate ECIES key if necessary */
      if(!isExist(ecies_privateKeyFileName) || !isExist(ecies_publicKeyFileName)){
        CryptoPP::OID c = curve(curveName);
        ECIES<ECP>::Decryptor d1(prng, c);
        //PrintPrivateKey(d0.GetKey());
        SavePrivateKey(d1.GetKey(),ecies_privateKeyFileName);

        ECIES<ECP>::Encryptor e1(d1);
        //PrintPublicKey(e0.GetKey());
        SavePublicKey(e1.GetKey(),ecies_publicKeyFileName);
      }

      /* Read Private Key */
      
      // Load public key in X.509 format
      FileSource fs( ecdsa_privateKeyFileName.str().c_str(), true );
      ecdsa_privateKey.Load( fs );
      bool result = ecdsa_privateKey.Validate( prng, 3 );
      if( !result ) {
        cout << "ECDSA Private Key Invalid!" << endl;
        exit(-1);
      }

      LoadPublicKey(e0.AccessPublicKey(), ecies_publicKeyFileName);
      e0.GetPublicKey().ThrowIfInvalid(prng, 3);

      LoadPrivateKey(d0.AccessPrivateKey(), ecies_privateKeyFileName);
      d0.GetPrivateKey().ThrowIfInvalid(prng, 3);

      string pubKey;
      SavePublicKey(e0.GetKey(), pubKey);
      //cout << "Public Key: " << pubKey << endl;


      /* Sign public key */
      // ECDSA<ECP, SHA256>::Signer signer( ecdsa_privateKey );
      // size_t siglen = signer.MaxSignatureLength();
      // string signature(siglen, 0x00);
      // siglen = signer.SignMessage( prng, (const byte*)pubKey.data(), pubKey.size(), (byte*)signature.data() );
      // signature.resize(siglen);

      // cout << siglen << endl;
      
      // ofstream sign_file;
      // sign_file.open(signatureFileName.str().c_str());
      // sign_file.write(signature.c_str(),siglen);
      // sign_file.close();

      /* Read signature of public key */
      stringstream signature2;
      ifstream sign_file2;
      sign_file2.open(signatureFileName.str().c_str());
      signature2 << sign_file2.rdbuf();

      // cout << signature2.str() << endl;

      // cout << pubKey.length() << "  " << signature2.str().length() << endl;

      int length[] = {pubKey.length(), signature2.str().length()};

      /* send the public key to client */
      if (send(new_fd, length, 8, 0) == -1)
          perror("send");

      /* send the public key to client */
      if (send(new_fd, pubKey.c_str(), (size_t) pubKey.length(), 0) == -1)
          perror("send");

      /* send the signature of public key to client */
      if (send(new_fd, signature2.str().c_str(), (size_t) signature2.str().length(), 0) == -1)
          perror("send");
   }


   /* Listen for client's transaction message */
   if ((numbytes=recv(new_fd, c_encoded, MAXDATASIZE-1, 0)) == -1) {
        perror("recv");
        exit(1);
    } else if (numbytes > 0) {
   
      c_encoded[numbytes]='\0';

      printf("\tReceived: %s\n", c_encoded);
      string decoded;
      string encoded(c_encoded);
      decoded = base64_decode(encoded);

      string plaintext;
      StringSource ss2 (decoded, true, new PK_DecryptorFilter(prng, d0, new StringSink(plaintext) ) );
      cout << "Decrypted Message: " << plaintext << endl;

      /* Sign and reply signature to client */
      ECDSA<ECP, SHA256>::Signer signer( ecdsa_privateKey );
      size_t siglen = signer.MaxSignatureLength();
      string receipt(siglen, 0x00);
      siglen = signer.SignMessage( prng, (const byte*)plaintext.data(), plaintext.size(), (byte*)receipt.data() );
      receipt.resize(siglen);

      string receipt_encoded = base64_encode(reinterpret_cast<const unsigned char*>(receipt.c_str()), receipt.length());
      cout << "Generated Receipt: " << receipt_encoded << endl;

      if (send(new_fd, receipt_encoded.c_str(), (size_t) receipt_encoded.length(), 0) == -1)
            perror("send");
    }



    


   
   // /* For TCP socket, ommunicate with the client using new_fd */
   // /* First, blocing waiting for message and then send back the message */
   // /* For the exercise, you have to comment out (or remove) the whole if/else block */
   //  if ((numbytes=recv(new_fd, curveName, MAXDATASIZE-1, 0)) == -1) {
   //      perror("recv");
   //      exit(1);
   //  } else if (numbytes > 0) {
   // /* if client side's connection is closed with bruteforce, recv() will return '0'
   // */
   //    curveName[numbytes]='\0';
   //    printf("\tReceived: %s\n", curveName);
        
   //    /* echo the message back */
   //      if (send(new_fd, curveName, numbytes, 0) == -1)
   //          perror("send");

   // }

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

void LoadPrivateKey(PrivateKey& key, const string& file)
{
    FileSource source(file.c_str(), true);
    key.Load(source);
}

void LoadPublicKey(PublicKey& key, const string& file)
{
    FileSource source(file.c_str(), true);
    key.Load(source);
}

void SavePrivateKey(const PrivateKey& key, string &s)
{
    StringSink sink(s);
    key.Save(sink);
}

void SavePublicKey(const PublicKey& key, string &s)
{
    StringSink sink(s);
    key.Save(sink);
}