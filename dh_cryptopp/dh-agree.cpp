// g++ -g3 -ggdb -O0 -I. -I/usr/include/cryptopp dh-agree.cpp -o dh-agree.exe -lcryptopp -lpthread
// g++ -g -O2 -I. -I/usr/include/cryptopp dh-agree.cpp -o dh-agree.exe -lcryptopp -lpthread

#include <iostream>
using std::cout;
using std::cerr;
using std::endl;

#include <string>
using std::string;

#include <stdexcept>
using std::runtime_error;

#include <sstream>
using std::istringstream;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "integer.h"
using CryptoPP::Integer;

#include "nbtheory.h"
using CryptoPP::ModularExponentiation;

#include "dh.h"
using CryptoPP::DH;

#include "secblock.h"
using CryptoPP::SecByteBlock;

#include <hex.h>
using CryptoPP::HexEncoder;

#include <filters.h>
using CryptoPP::StringSink;

int main(int argc, char** argv)
{
	unsigned int bits = 1024;
	AutoSeededRandomPool rndA, rndB;
	try
	{

		// if(argc >= 2)
		// {
		// 	istringstream iss(argv[1]);
		// 	iss >> bits;

		// 	if(iss.fail())
		// 		throw runtime_error("Failed to parse size in bits");

		// 	if(bits < 6)
		// 		throw runtime_error("Invalid size in bits");
		// }

		cout << "Generating prime of size " << bits << " and generator" << endl;

		// Safe primes are of the form p = 2q + 1, p and q prime.
		// These parameters do not state a maximum security level based
		// on the prime subgroup order. In essence, we get the maximum
		// security level. There is no free lunch: it means more modular
		// mutliplications are performed, which affects performance.

		// For a compare/contrast of meeting a security level, see dh-init.zip.
		// Also see http://www.cryptopp.com/wiki/Diffie-Hellman and
		// http://www.cryptopp.com/wiki/Security_level .

		// CryptoPP::DL_GroupParameters_IntegerBased::GenerateRandom (gfpcrypt.cpp)
		// CryptoPP::PrimeAndGenerator::Generate (nbtheory.cpp)
		DH dh;
		
		dh.AccessGroupParameters().GenerateRandomWithKeySize(rndA, bits);

		if(!dh.GetGroupParameters().ValidateGroup(rndA, 3))
			throw runtime_error("Failed to validate prime and generator");

		size_t count = 0;

		const Integer& p = dh.GetGroupParameters().GetModulus();
		count = p.BitCount();
		cout << "P (" << std::dec << count << "): " << std::hex << p << endl;
		
		const Integer& q = dh.GetGroupParameters().GetSubgroupOrder();
		count = q.BitCount();
		cout << "Q (" << std::dec << count << "): " << std::hex << q << endl;

		const Integer& g = dh.GetGroupParameters().GetGenerator();
		count = g.BitCount();
		cout << "G (" << std::dec << count << "): " << std::dec << g << endl;

		// http://groups.google.com/group/sci.crypt/browse_thread/thread/7dc7eeb04a09f0ce
		Integer v = ModularExponentiation(g, q, p);
		if(v != Integer::One())
			throw runtime_error("Failed to verify order of the subgroup");

		return;


		// RFC 5114, 1024-bit MODP Group with 160-bit Prime Order Subgroup
		// http://tools.ietf.org/html/rfc5114#section-2.1
		Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
			"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
			"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
			"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
			"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
			"DF1FB2BC2E4A4371");

		Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
			"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
			"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
			"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
			"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
			"855E6EEB22B3B2E5");

		Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");		

		// Schnorr Group primes are of the form p = rq + 1, p and q prime. They
		// provide a subgroup order. In the case of 1024-bit MODP Group, the
		// security level is 80 bits (based on the 160-bit prime order subgroup).		

		// For a compare/contrast of using the maximum security level, see
		// dh-agree.zip. Also see http://www.cryptopp.com/wiki/Diffie-Hellman
		// and http://www.cryptopp.com/wiki/Security_level .

		DH dhA, dhB;
		

		dhA.AccessGroupParameters().Initialize(p, q, g);
		dhB.AccessGroupParameters().Initialize(p, q, g);

		if(!dhA.GetGroupParameters().ValidateGroup(rndA, 3) ||
		   !dhB.GetGroupParameters().ValidateGroup(rndB, 3))
			throw runtime_error("Failed to validate prime and generator");

		//size_t count = 0;

		p = dhA.GetGroupParameters().GetModulus();
		q = dhA.GetGroupParameters().GetSubgroupOrder();
		g = dhA.GetGroupParameters().GetGenerator();

		// http://groups.google.com/group/sci.crypt/browse_thread/thread/7dc7eeb04a09f0ce
		v = ModularExponentiation(g, q, p);
		if(v != Integer::One())
			throw runtime_error("Failed to verify order of the subgroup");

		//////////////////////////////////////////////////////////////

		SecByteBlock privA(dhA.PrivateKeyLength());
		SecByteBlock pubA(dhA.PublicKeyLength());
		dhA.GenerateKeyPair(rndA, privA, pubA);

		SecByteBlock privB(dhB.PrivateKeyLength());
		SecByteBlock pubB(dhB.PublicKeyLength());
		dhB.GenerateKeyPair(rndB, privB, pubB);

		cout << "Generated key pair!" << endl;

		//////////////////////////////////////////////////////////////

		if(dhA.AgreedValueLength() != dhB.AgreedValueLength())
			throw runtime_error("Shared secret size mismatch");

		SecByteBlock sharedA(dhA.AgreedValueLength()), sharedB(dhB.AgreedValueLength());

		if(!dhA.Agree(sharedA, privA, pubB))
			throw runtime_error("Failed to reach shared secret (1A)");

		if(!dhB.Agree(sharedB, privB, pubA))
			throw runtime_error("Failed to reach shared secret (B)");

		count = std::min(dhA.AgreedValueLength(), dhB.AgreedValueLength());
		if(!count || 0 != memcmp(sharedA.BytePtr(), sharedB.BytePtr(), count))
			throw runtime_error("Failed to reach shared secret");

		//////////////////////////////////////////////////////////////

		Integer a, b;

		a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
		cout << "Shared secret (A): " << std::hex << a << endl;

		b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
		cout << "Shared secret (B): " << std::hex << b << endl;
	}

	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		return -2;
	}

	catch(const std::exception& e)
	{
		cerr << e.what() << endl;
		return -1;
	}

	return 0;
}

