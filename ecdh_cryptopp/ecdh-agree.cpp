// g++ -g3 -ggdb -O0 -DDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread
// g++ -g -O2 -DNDEBUG ecdh-agree.cpp -o ecdh-agree.exe -lcryptopp -lpthread

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
using CryptoPP::AutoSeededX917RNG;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/eccrypto.h"
using CryptoPP::ECP;
using CryptoPP::ECDH;

#include "cryptopp/secblock.h"
using CryptoPP::SecByteBlock;

#include "cryptopp/oids.h"
using CryptoPP::OID;

// ASN1 is a namespace, not an object
#include "cryptopp/asn.h"
using namespace CryptoPP::ASN1;

#include "cryptopp/integer.h"
using CryptoPP::Integer;

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

int main( int argc, char** arg) {
    struct timeval stop, start;     // start and stop time
    string curve_name;

    if(argc!=2){
        cout << "usage: " << arg[0] << " [curve]\n";
        exit(-1);
    } else {
        curve_name = arg[1];
    }

    OID CURVE = curve(curve_name);
    AutoSeededX917RNG<AES> rng;

    ECDH < ECP >::Domain dhA( CURVE ), dhB( CURVE );

    // Don't worry about point compression. Its amazing that Certicom got
    // a patent for solving an algebraic equation....
    // dhA.AccessGroupParameters().SetPointCompression(true);
    // dhB.AccessGroupParameters().SetPointCompression(true);

    SecByteBlock privA(dhA.PrivateKeyLength()), pubA(dhA.PublicKeyLength());
    SecByteBlock privB(dhB.PrivateKeyLength()), pubB(dhB.PublicKeyLength());

    dhA.GenerateKeyPair(rng, privA, pubA);

    dhB.GenerateKeyPair(rng, privB, pubB);

    if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
	throw runtime_error("Shared secret size mismatch");

    SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());
    gettimeofday(&start, NULL);
    const bool rtn1 = dhA.Agree(sharedA, privA, pubB);
    gettimeofday(&stop, NULL);
    const bool rtn2 = dhB.Agree(sharedB, privB, pubA);
    if(!rtn1 || !rtn2)
	throw runtime_error("Failed to reach shared secret (A)");

    const bool rtn3 = sharedA.size() == sharedB.size();
    if(!rtn3)
	throw runtime_error("Failed to reach shared secret (B)");

    Integer a, b;

    a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
    //cout << "(A): " << std::hex << a << endl;

    b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
    //cout << "(B): " << std::hex << b << endl;

    const bool rtn4 = a == b;
    if(!rtn4)
	throw runtime_error("Failed to reach shared secret (C)");

    //cout << "Agreed to shared secret" << endl;
    cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << endl;

    return 0;
}
