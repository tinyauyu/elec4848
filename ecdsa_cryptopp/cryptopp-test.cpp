// g++ -g3 -ggdb -O0 -DDEBUG -Wall -Wextra cryptopp-test.cpp -o cryptopp-test.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG -Wall -Wextra cryptopp-test.cpp -o cryptopp-test.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;
#include <iomanip> // This might be necessary

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

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>

#include <sstream>
using std::stringstream;

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
    stringstream priKeyFileName, pubKeyFileName;    


    // check arguments

    if(argc!=3){
        cout << "usage: " << arg[0] << " [curve] [message]\n";
        exit(-1);
    } else {
        curve_name = arg[1];
        message = arg[2];
    }

    //////////////////////////////////////////////////////

    // Generate private key
    ECDSA<ECP, SHA256>::PrivateKey privKey;
    privKey.Initialize( prng, curve(curve_name) );
    privKey.Save( privateKey );
    priKeyFileName << "ecdsa-private-" << curve_name << ".key";
    FileSink pri( priKeyFileName.str().c_str() );
    privKey.Save( pri );

    // Create public key
    ECDSA<ECP, SHA256>::PublicKey pubKey;
    privKey.MakePublicKey( pubKey );
    pubKey.Save( publicKey );
    pubKeyFileName << "ecdsa-public-" << curve_name << ".key";
    FileSink pub( pubKeyFileName.str().c_str() );
    pubKey.Save( pub );

    //////////////////////////////////////////////////////    

    // Load private key (in ByteQueue, PKCS#8 format)
    ECDSA<ECP, SHA256>::Signer signer( privateKey );

    // Determine maximum size, allocate a string with that size
    size_t siglen = signer.MaxSignatureLength();
    string signature(siglen, 0x00);

    // Sign, and trim signature to actual size
    gettimeofday(&start, NULL);
    siglen = signer.SignMessage( prng, (const byte*)message.data(), message.size(), (byte*)signature.data() );
    signature.resize(siglen);
    gettimeofday(&stop, NULL);

    cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << " ";

    // //////////////////////////////////////////////////////    

    // Load public key (in ByteQueue, X509 format)
    cout << "Length: " << publicKey.MaxRetrievable() << endl;
    ECDSA<ECP, SHA256>::Verifier verifier( publicKey );
    gettimeofday(&start, NULL);
    bool result = verifier.VerifyMessage( (const byte*)message.data(), message.size(), (const byte*)signature.data(), signature.size() );
    gettimeofday(&stop, NULL);

    if(result){
        cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << endl;
        //cout << "signature: " << std::hex << signature << endl;
    }else
        cerr << "Failed to verify signature on message" << endl;

    return 0;
}
