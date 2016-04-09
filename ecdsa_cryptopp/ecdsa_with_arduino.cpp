// g++ -g3 -ggdb -O0 -DDEBUG -Wall -Wextra cryptopp-test.cpp -o cryptopp-test.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -Wall -Wextra cryptopp-test.cpp -o cryptopp-test.exe -lcryptopp -lpthread

#include <stdio.h>
#include <stdlib.h>
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


int main( int argc, char** arg ) {

    AutoSeededRandomPool prng;
    ByteQueue privateKey, publicKey;
    string curve_name, message;
    struct timeval stop, start;     // start and stop time


    // check arguments
    /*
    if(argc!=3){
        cout << "usage: " << arg[0] << " [curve] [message]\n";
        exit(-1);
    } else {
        curve_name = arg[1];
        message = arg[2];
    }
    */
    
    string publicKey_s =    "3E5DAC6B352D67C09F8C111B57A65AC3FFAD08B90B89711B72A4A0EF8E84F47D"
                            "EFD9CD12A3F91189ECDFFE6A8808B6B42C3C36F224898EB7B429D4FB1D1F1FB7";
    string privateKey_s = "E12FB77565A6C209B1D9F6C3F6546CF5AEFE0666D3357504A7B98F78BDE3B7EC";
    string sign_s = "179809B5053715552085412884F96B49EAD708B0CD03336C2C787E9C5E3E4C1A52C33E6A97C376F20C0255D585C0285B150A61F48D344ADE06ED6C1A4AF4BEF9";
    
    string signature;


    message = "This is an apple!";
    // string message_hex;
    // StringSource ss3(message, true,
    //     new HexEncoder(
    //         new StringSink(message_hex)
    //     ) // HexEncoder
    // ); // StringSource
    // cout << "Message: " << message_hex << endl;

    // Construct the Public Key
    HexDecoder decoder;
    decoder.Put((byte*)publicKey_s.data(), publicKey_s.size());
    decoder.MessageEnd();

    ECP::Point q;
    size_t len = decoder.MaxRetrievable();
    assert(len == SHA256::DIGESTSIZE * 2);

    q.identity = false;
    q.x.Decode(decoder, len/2);
    q.y.Decode(decoder, len/2);

    ECDSA<ECP, SHA256>::PublicKey pubKey;
    pubKey.Initialize( secp256r1(), q );
    pubKey.Save( publicKey );

    // Construct the Private Key
    HexDecoder decoder2;
    decoder2.Put((byte*)privateKey_s.data(), privateKey_s.size());
    decoder2.MessageEnd();

    Integer x;
    x.Decode(decoder2, decoder2.MaxRetrievable());

    ECDSA<ECP, SHA256>::PrivateKey priKey;
    priKey.Initialize(secp256r1(), x);
    priKey.Save( privateKey );

    cout << "Public key constructed!" << endl;

    //Decode the signature
    StringSource ss(sign_s, true,
        new HexDecoder(
            new StringSink(signature)
        ) // HexDecoder
    ); // StringSource

    cout << "signatrue decoded: ";
    for (int i=0; i<signature.size(); i++){
        cout << std::hex << (unsigned int) signature.data()[i] << ":";
    }
    
    cout << "signature decoded!" << endl;

    //////////////////////////////////////////////////////

    // // Generate private key
    // ECDSA<ECP, SHA256>::PrivateKey privKey;
    // privKey.Initialize( prng, curve(curve_name) );
    // privKey.Save( privateKey );

    // // Create public key
    // ECDSA<ECP, SHA256>::PublicKey pubKey;
    // privKey.MakePublicKey( pubKey );
    // pubKey.Save( publicKey );

    ////////////////////////////////////////////////////    
    
    // // Load private key (in ByteQueue, PKCS#8 format)
    // ECDSA<ECP, SHA256>::Signer signer( privateKey );

    // // Determine maximum size, allocate a string with that size
    // size_t siglen = signer.MaxSignatureLength();
    // string signature(siglen, 0x00);

    // // Sign, and trim signature to actual size
    // gettimeofday(&start, NULL);
    // siglen = signer.SignMessage( prng, (const byte*)message.data(), message.size(), (byte*)signature.data() );
    // signature.resize(siglen);
    // gettimeofday(&stop, NULL);

    // cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << " ";

    ////////////////////////////////////////////////////    
    
    // Load public key (in ByteQueue, X509 format)
    ECDSA<ECP, SHA256>::Verifier verifier( publicKey );

    gettimeofday(&start, NULL);
    bool result = verifier.VerifyMessage( (const byte*)message.data(), message.size(), (const byte*)signature.data(), signature.size() );
    gettimeofday(&stop, NULL);

    if(result){
        cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << endl;

        // encode signature
        string signature_s;

        StringSource ss2(signature, true,
            new HexEncoder(
                new StringSink(signature_s)
            ) // HexEncoder
        ); // StringSource
        cout << "Signature: " << signature_s << endl;
        cout << "message length: " << message.size() << endl;
        cout << "signature length: " << signature.size() << endl;

    } else
        cerr << "Failed to verify signature on message" << endl;

    return 0;
}
