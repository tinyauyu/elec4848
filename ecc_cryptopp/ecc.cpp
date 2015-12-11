// g++ -DDEBUG=1 -g3 -O0 -Wall -Wextra cryptopp-ecies-test.cpp -o cryptopp-ecies-test.exe -lcryptopp
// g++ -DNDEBUG=1 -g3 -O2 -Wall -Wextra cryptopp-ecies-test.cpp -o cryptopp-ecies-test.exe -lcryptopp

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

#include <map>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out = cout);
void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out = cout);

void SavePrivateKey(const PrivateKey& key, const string& file = "ecies.private.key");
void SavePublicKey(const PublicKey& key, const string& file = "ecies.public.key");

void LoadPrivateKey(PrivateKey& key, const string& file = "ecies.private.key");
void LoadPublicKey(PublicKey& key, const string& file = "ecies.public.key");

static const string message("Now is the time for all good men to come to the aide of their country.");
//static const string message("00000000000000000000000000000000000000000000000000000000000000");

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

int main(int argc, char* argv[])
{
    string curveName;
    string msg;
    char outputType;

    if(argc!=3){
        cout << "usage: ./ecc.o [curve] [message]";
        exit(-1);
    } else {
        curveName = argv[1];
        msg = argv[2];
    }

    string privateKeyFileName = "ecc-private-";
    privateKeyFileName.append(curveName);
    privateKeyFileName.append(".key");
    string publicKeyFileName = "ecc-public-";
    publicKeyFileName.append(curveName);
    publicKeyFileName.append(".key");

    AutoSeededRandomPool prng;

    if(!isExist(privateKeyFileName) || !isExist(publicKeyFileName)){
        AutoSeededRandomPool prng;
        CryptoPP::OID c = curve(curveName);
        ECIES<ECP>::Decryptor d1(prng, c);
        //PrintPrivateKey(d0.GetKey());
        SavePrivateKey(d1.GetKey(),privateKeyFileName);

        ECIES<ECP>::Encryptor e1(d1);
        //PrintPublicKey(e0.GetKey());
        SavePublicKey(e1.GetKey(),publicKeyFileName);
    }

    ECIES<ECP>::Decryptor d0;
    LoadPrivateKey(d0.AccessPrivateKey(), privateKeyFileName);
    d0.GetPrivateKey().ThrowIfInvalid(prng, 3);
    
    ECIES<ECP>::Encryptor e0;
    LoadPublicKey(e0.AccessPublicKey(), publicKeyFileName);
    e0.GetPublicKey().ThrowIfInvalid(prng, 3);
    


    
    
    
    /////////////////////////////////////////////////
    // Part four - encrypt/decrypt with e0/d1

    string em0; // encrypted message

    //PK_EncryptorFilter* filter = new PK_EncryptorFilter (prng, e0, new StringSink(em0));
    struct timeval stop, start;     // start and stop time
    gettimeofday(&start, NULL);
    
        StringSource ss1 (msg, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0) ) );
        //em0 = "";
        //new StringSource (msg, true, filter);
        //string encoded; // encoded (pretty print)
        //StringSource ss3(em0, true, new HexEncoder(new StringSink(encoded)));

        //cout << "Ciphertext (" << encoded.size()/2 << "):" << encoded << endl << "  ";
        //cout << encoded << endl;
    
    gettimeofday(&stop, NULL);

    

    //cout << "Time for encryption: " << (stop.tv_usec - start.tv_usec)/1000000.0 + (stop.tv_sec - start.tv_sec) << "s\n";
    //cout << (stop.tv_usec - start.tv_usec)/1000000.0 + (stop.tv_sec - start.tv_sec) << "\n";
    //if(outputType == 'e'){
        cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << " ";
    //}

    //StringSource ss1 (message, true, new PK_DecryptorFilter(prng, d0, new StringSink(em0) ) );
    string dm0; // decrypted message
    gettimeofday(&start, NULL);
    StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm0) ) );
    gettimeofday(&stop, NULL);
    //cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << "\n";
    
    //StringSource ss2 (em0, true, new PK_EncryptorFilter(prng, e0, new StringSink(dm0) ) );
    
    //if(outputType == 'd'){
        cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << "\n";
    //}
    
    
    //cout << "Ciphertext (" << encoded.size()/2 << "):" << endl << "  ";
    //cout << encoded << endl;
    //cout << "Recovered:" << endl << "  ";
    //cout << dm0 << endl;

    if(dm0!=msg){
        cout << "ERROR!" << endl;
    }
    
    return 0;
}

void SavePrivateKey(const PrivateKey& key, const string& file)
{
    FileSink sink(file.c_str());
    key.Save(sink);
}

void SavePublicKey(const PublicKey& key, const string& file)
{
    FileSink sink(file.c_str());
    key.Save(sink);
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

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out)
{
    const std::ios_base::fmtflags flags = out.flags();
    
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Base precomputation
    const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
    // Public Key (just do the exponentiation)
    const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;
    
    out << "Private Exponent (multiplicand): " << endl;
    out << "  " << std::hex << key.GetPrivateExponent() << endl;

    out << endl;
    out.flags(flags);
}

void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out)
{
    const std::ios_base::fmtflags flags = out.flags();
    
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Public key
    const ECPPoint& point = key.GetPublicElement();
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;

    out << endl;
    out.flags(flags);
}
