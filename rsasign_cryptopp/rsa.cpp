// Sample.cpp

#include <cryptopp/rsa.h>
using CryptoPP::RSA;
using CryptoPP::RSASS;
using CryptoPP::InvertibleRSAFunction;
using CryptoPP::RSAES_OAEP_SHA_Encryptor;
using CryptoPP::RSAES_OAEP_SHA_Decryptor;

#include <cryptopp/sha.h>
using CryptoPP::SHA256;

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

#include <cryptopp/pssr.h>
using CryptoPP::PSS;

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
    string message, keyLength_s;
    struct timeval stop, start;     // start and stop time

    if(argc!=3){
        cout << "usage: ./rsa.o [key_length] [message]\n";
        exit(-1);
    } else {
        keyLength_s = argv[1];
        keyLength = atoi(keyLength_s.c_str());
        message = argv[2];
    }

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

        string plain=message, cipher, recovered;

        // Signer object
        RSASS<PSS, SHA256>::Signer signer(privateKey);

        // Create signature space
        size_t length = signer.MaxSignatureLength();
        SecByteBlock signature(length);

        gettimeofday(&start, NULL);

        // Sign message
        length = signer.SignMessage(rng, (const byte*) message.c_str(),
            message.length(), signature);

        // Resize now we know the true size of the signature
        signature.resize(length);

        gettimeofday(&stop, NULL);

        cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << " ";

        // Verifier object
        RSASS<PSS, SHA256>::Verifier verifier(publicKey);

        gettimeofday(&start, NULL);

        // Verify
        bool result = verifier.VerifyMessage((const byte*)message.c_str(),
            message.length(), signature, signature.size());

        gettimeofday(&stop, NULL);

        // Result
        if(true == result) {
            cout << (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000 << endl;
        } else {
            cout << "Message verification failed" << endl;
        }

	return 0;
}


