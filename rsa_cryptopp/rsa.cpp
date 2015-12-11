// Sample.cpp

#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include <cryptopp/sha.h>
using CryptoPP::SHA1;

#include <cryptopp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <cryptopp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/secblock.h>
using CryptoPP::SecByteBlock;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;
using CryptoPP::DecodingResult;

#include <string>
using std::string;

#include <exception>
using std::exception;

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <assert.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <unistd.h>

void Load(const string& filename,
        CryptoPP::BufferedTransformation& bt) {
    CryptoPP::FileSource file(filename.c_str(), true);
    file.TransferTo(bt);
    bt.MessageEnd();
}

void LoadPublicKey(const string& filename,
        CryptoPP::PublicKey& key) {
    CryptoPP::ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void LoadPrivateKey(const string& filename,
        CryptoPP::PrivateKey& key) {
    CryptoPP::ByteQueue queue;
    Load(filename, queue);
    key.Load(queue);
}

void Save(const string& filename,
        const CryptoPP::BufferedTransformation& bt) {
    CryptoPP::FileSink file(filename.c_str());
    bt.CopyTo(file);
    file.MessageEnd();
}

void SavePrivateKey(const string& filename,
        const CryptoPP::PrivateKey& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

void SavePublicKey(const string& filename,
        const CryptoPP::PublicKey& key) {
    CryptoPP::ByteQueue queue;
    key.Save(queue);
    Save(filename, queue);
}

inline bool isExist (const std::string& name) {
    return ( access( name.c_str(), F_OK ) != -1 );
}



int main(int argc, char* argv[])
{
    int keyLength = 2048;
    char outputType = 'e';
    string msg, keyLength_s;

    if(argc!=3){
        cout << "usage: ./rsa.o [key_length] [message]\n";
        exit(-1);
    } else {
        keyLength_s = argv[1];
        keyLength = atoi(keyLength_s.c_str());
        msg = argv[2];
    }

    try
    {
        ////////////////////////////////////////////////
        // Generate keys
        RSA::PrivateKey privateKey;
        RSA::PublicKey publicKey;
        AutoSeededRandomPool rng;

        string privateKeyFileName = "rsa-private-";
        privateKeyFileName.append(keyLength_s);
        privateKeyFileName.append(".key");
        string publicKeyFileName = "rsa-public-";
        publicKeyFileName.append(keyLength_s);
        publicKeyFileName.append(".key");

        if(!isExist(privateKeyFileName) || !isExist(publicKeyFileName)){

            InvertibleRSAFunction parameters;
            parameters.GenerateRandomWithKeySize( rng, keyLength );

            RSA::PrivateKey newPrivateKey( parameters );
            RSA::PublicKey newPublicKey( parameters );

            SavePrivateKey(privateKeyFileName, newPrivateKey);
            SavePublicKey(publicKeyFileName, newPublicKey);

        }

        LoadPrivateKey(privateKeyFileName, privateKey);
        LoadPublicKey(publicKeyFileName, publicKey);

        string plain=msg, cipher, recovered;

        ////////////////////////////////////////////////
        // Encryption
        RSAES_OAEP_SHA_Encryptor e( publicKey );

        struct timeval stop, start;     // start and stop time
        gettimeofday(&start, NULL);

        StringSource ss1( plain, true,
            new PK_EncryptorFilter( rng, e,
                new StringSink( cipher )
            ) // PK_EncryptorFilter
         ); // StringSource

        gettimeofday(&stop, NULL);

        ////////////////////////////////////////////////
        ////////////////////////////////////////////////

        //if(outputType == 'e'){
            cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << " ";
        //}

        //cout << cipher << endl;

        ////////////////////////////////////////////////
        // Decryption
        RSAES_OAEP_SHA_Decryptor d( privateKey );

        gettimeofday(&start, NULL);

        StringSource ss2( cipher, true,
            new PK_DecryptorFilter( rng, d,
                new StringSink( recovered )
            ) // PK_EncryptorFilter
         ); // StringSource

        gettimeofday(&stop, NULL);

        //if(outputType == 'd'){
            cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << "\n";
        //}        

        //cout << recovered << endl;

        assert( plain == recovered );
    }
    catch( CryptoPP::Exception& e )
    {
        cerr << "Caught Exception..." << endl;
        cerr << e.what() << endl;
    }

	return 0;
}


