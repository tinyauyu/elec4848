/*
** echo_client.c -- Demo program: echo client
**
** 
**
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>  /* for perror() */
#include <string.h>
/* for using socket functions */
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

/* for encryption functions */
#include <iostream>
using std::ostream;
using std::cout;
using std::endl;

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

    

#define PORT 49950  // the port used by target server
                    // it must be unique within the server host machine
                    // you can change this number to a port number 
                    // within your allocated range

#define MAXDATASIZE 10000 // max number of bytes we can get at once 

void LoadPrivateKey(PrivateKey& key, const string& str);
void LoadPublicKey(PublicKey& key, const string& str);


int main(int argc, char *argv[])
{

    string curveName;
    string msg;
    AutoSeededRandomPool prng;
    ECIES<ECP>::Encryptor e0;
    ECIES<ECP>::Decryptor d0;

    int sockfd, numbytes;  
    char pubKeyReceived[MAXDATASIZE];
    char signatureReceived[MAXDATASIZE];
    char receiptReceived[MAXDATASIZE];
    struct hostent *he;
    struct sockaddr_in peer_addr;   //server's address information 

    if (argc != 4) {
        fprintf(stderr,"usage: client hostname curveName message\n");
        exit(1);
    } else {
        curveName = argv[2];
        msg = argv[3];
    }

    /* Read the manpage and slide# 27 of 03-SocketProgramming.pdf to learn how
       to use gethostbyname() function
    */
    if ((he=gethostbyname(argv[1])) == NULL) {  // get the host info 
        perror("gethostbyname");
        exit(1);
    }

    /* Create the socket for TCP communication */
    /* For the exercise, change this part to use UDP */
    if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    /* Prepare the socket address structure of target server 
    */
    peer_addr.sin_family = AF_INET;    // host byte order 
    peer_addr.sin_port = htons(PORT);  // short, network byte order 
    peer_addr.sin_addr = *((struct in_addr *)he->h_addr); // already in network byte order
    memset(&(peer_addr.sin_zero), '\0', 8);  // zero the rest of the struct 

    /* Initiate connection to server */
    /* For the exercise, you can comment out (or remove) this part */
    if (connect(sockfd, (struct sockaddr *)&peer_addr, sizeof(struct sockaddr)) == -1) {
        perror("connect");
        exit(1);
    }
    
    /* For the exercise, you can comment out (or remove) this part */
    printf("Connection established.\n\n");
    
    /* Keep this one for requesting input from user */
    cout << "Using curve: " << curveName << endl;
    
    /* Send the message via TCP socket */
    /* For the exercise, change this one to use sendto() for UDP */
    if (send(sockfd, curveName.c_str(), (size_t) curveName.length(), 0) == -1)
        perror("send");

    int length[] = {0,0};

    if ((numbytes=recv(sockfd, length, 8, 0)) == -1) {
        perror("recv");
        exit(1);
    }

    //cout << length[0] << "  " << length[1] << endl;

    /* Block waiting for receiving message from server */
    /* For the exercise, you can change this to use recvfrom() */
    /* Actually, you don't need to change this if you don't care
       who sent you the message */
    if ((numbytes=recv(sockfd, pubKeyReceived, length[0], 0)) == -1) {
        perror("recv");
        exit(1);
    }
    pubKeyReceived[numbytes] = '\0';

    /* Receive Public Key */
    string pubkey_str(pubKeyReceived, numbytes);
    LoadPublicKey(e0.AccessPublicKey(), pubkey_str);
    e0.GetPublicKey().ThrowIfInvalid(prng, 3);

    //printf("Echo received: %s\n\n",buf);

    if ((numbytes=recv(sockfd, signatureReceived, length[1], 0)) == -1) {
        perror("recv");
        exit(1);
    }
    signatureReceived[numbytes] = '\0';
    string signature_str(signatureReceived, numbytes);

    //cout << "Signature: " << signature_str << endl;

    /* Verify Public Key */
    stringstream ecdsa_publicKeyFileName;
    ecdsa_publicKeyFileName << "ca-public-" << curveName << ".key";

    ECDSA<ECP, SHA256>::PublicKey ecdsa_publicKey;
    FileSource fs( ecdsa_publicKeyFileName.str().c_str() , true );
    ecdsa_publicKey.Load( fs );
    bool result = ecdsa_publicKey.Validate( prng, 3 );
    if( !result ) {
        cout << "ECDSA Public Key Invalid!" << endl;
        exit(-1);
    }

    ECDSA<ECP, SHA256>::Verifier verifier( ecdsa_publicKey );
    result = verifier.VerifyMessage( (const byte*)pubkey_str.data(), pubkey_str.size(), (const byte*)signature_str.data(), signature_str.size() );
    if ( !result ) {
        cout << "Public Key Verification Failed!" << endl;
        exit(-1);
    } else {
        cout << "Public Key Verified." << endl;
    }

    /* Encrypt Transaction Message */
    cout << "Encrypting Message: " << msg << endl;
    string ciphertext, c_encoded;
    StringSource ss1 (msg, true, new PK_EncryptorFilter(prng, e0, new StringSink(ciphertext) ) );
    
    c_encoded = base64_encode(reinterpret_cast<const unsigned char*>(ciphertext.c_str()), ciphertext.length());
    cout << "Ciphertext: " << c_encoded << endl;
    if (send(sockfd, c_encoded.c_str(), (size_t) c_encoded.size(), 0) == -1)
        perror("send");

    /* Get Receipt from server */
    if ((numbytes=recv(sockfd, receiptReceived, length[1], 0)) == -1) {
        perror("recv");
        exit(1);
    }
    receiptReceived[numbytes] = '\0';
    string receipt_encoded(receiptReceived, numbytes);
    cout << "Receipt received: " << receipt_encoded << endl;
    string receipt = base64_decode(receipt_encoded);



    /* close the socket */
    close(sockfd);

    return 0;
}

void LoadPrivateKey(PrivateKey& key, const string& str)
{
    StringSource source(str, true);
    key.Load(source);
}

void LoadPublicKey(PublicKey& key, const string& str)
{
    StringSource source(str, true);
    key.Load(source);
}