// g++ -g3 -ggdb -O0 -I. -I/usr/include/cryptopp dh-param.cpp -o dh-param.exe -lcryptopp -lpthread
// g++ -g -O2 -I. -I/usr/include/cryptopp dh-param.cpp -o dh-param.exe -lcryptopp -lpthread

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

int main(int argc, char** argv)
{
	AutoSeededRandomPool rnd;
	unsigned int bits = 1024;

	try
	{
		if(argc >= 2)
		{
			istringstream iss(argv[1]);
			iss >> bits;

			if(iss.fail())
				throw runtime_error("Failed to parse size in bits");

			if(bits < 6)
				throw runtime_error("Invalid size in bits");
		}

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
		if (bits == 1024){
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

			dh.AccessGroupParameters().Initialize(p, q, g);	
		 } else if (bits == 2048){
		 	Integer p("0x8f150e804f08a0685cf8c6abb49a4fd21c6bfd112c26c3984214f271613cfb9604bafbe5cecf6bd665a9460c6eb6233e3377a9d3a5800bfa85fe330c1d333eb1c8afcde60ff56da99ad00ca7463466b6c2f331876666da316d5b347382e082b346c061bffe2513e6ec5fe69193d77b2087dcd0bb3da9f1c13da1fcf22df96912f554d60c5b14c23de802d5e1018fed322414445d0b2ae895b89ce9643ed11911a5d7cee781ed6ec20730c91a72a65d90d43848d43f39d42504873809c011dbf2bec5fab99bfb30d42219fd1649f5d3c3a24e9de9dcac8835c30f9e34e99bebf9ff977cd7b62f4ecd2fb8bb2fe1d9f48d7d018d1508648272af14d7bd7231af0fh");

			Integer g("0x2");

			Integer q("0x478a8740278450342e7c6355da4d27e90e35fe88961361cc210a7938b09e7dcb025d7df2e767b5eb32d4a306375b119f19bbd4e9d2c005fd42ff19860e999f58e457e6f307fab6d4cd680653a31a335b617998c3b3336d18b6ad9a39c1704159a36030dfff1289f3762ff348c9ebbd9043ee685d9ed4f8e09ed0fe7916fcb4897aaa6b062d8a611ef4016af080c7f699120a222e8595744adc4e74b21f688c88d2ebe773c0f6b7610398648d39532ec86a1c246a1f9cea1282439c04e008edf95f62fd5ccdfd986a110cfe8b24fae9e1d1274ef4ee56441ae187cf1a74cdf5fcffcbbe6bdb17a76697dc5d97f0ecfa46be80c68a84324139578a6bdeb918d787h");

			dh.AccessGroupParameters().Initialize(p, q, g);	
		 } else if (bits == 3072){

		 	Integer p("0xfe263289d0b0f83af19204ff23f189890b98dd61e03958894fd46c3d40dc16157a4227392f23806c9d6297eb91432bd631b177f4eed1acac8349f101f2a6d3cba49ffcc030d2de4c7532fa70f7d8dc677341a70e018e9e6d31b04b71d8ac9e23ec40352a68428c2015c13f622958d5c13cbf26e5ab1f91068258d6182051a56229d8f67cdec4a25798f7a1f1e7d8a74dda05ed0563d90d12aa1f6101e81279f9fc64c3e38b2ae23ec5f4ef5e4e06ecaf09fe375f7accd47c420b0026a2e4f3bbb7da6a5bb619b2232d10f35be8be55544c1e394d17a699b23b1a156d5a381304377994e0496b4b0aed8668bcdb4faf2e401934ff3ea214c70cd3a5845b185a533b2aaf415a100bb44402c3fd1455c85b5a01e7dc71ab85e28d89cefe42def3512cee47e81f0db07d2ff0899620910c428c723c45dcaa5a0c4496cf96cf54ad706c3f4ab6da69c0f355689172239be9874037732c474384c9fbe39ec7c0cd9890e8bea83290d1588bb073013838cb430e0988c2585ca4e31d7f32bc8ceb4ef093h");

			Integer g("0x3");

			Integer q("0x7f131944e8587c1d78c9027f91f8c4c485cc6eb0f01cac44a7ea361ea06e0b0abd21139c9791c0364eb14bf5c8a195eb18d8bbfa7768d65641a4f880f95369e5d24ffe6018696f263a997d387bec6e33b9a0d38700c74f3698d825b8ec564f11f6201a95342146100ae09fb114ac6ae09e5f9372d58fc883412c6b0c1028d2b114ec7b3e6f62512bcc7bd0f8f3ec53a6ed02f682b1ec8689550fb080f4093cfcfe3261f1c595711f62fa77af2703765784ff1bafbd666a3e21058013517279dddbed352ddb0cd911968879adf45f2aaa260f1ca68bd34cd91d8d0ab6ad1c09821bbcca7024b5a58576c3345e6da7d797200c9a7f9f510a638669d2c22d8c2d299d9557a0ad0805da220161fe8a2ae42dad00f3ee38d5c2f146c4e77f216f79a8967723f40f86d83e97f844cb1048862146391e22ee552d06224b67cb67aa56b8361fa55b6d34e079aab448b911cdf4c3a01bb99623a1c264fdf1cf63e066cc48745f54194868ac45d839809c1c65a18704c4612c2e52718ebf995e4675a77849h");

			dh.AccessGroupParameters().Initialize(p, q, g);	
		 } else if (bits == 7680){

		 	Integer p("0xb73a683e8d87cc0594fc30e78f9bbdba423f245ddf40108486dbf6bd1fed1a78f5f4873677709be8d162c1c838c296ebc163d63ad1af856c35ebe297ec0ed766ebf4b7fe09ded19f0a5d4ba079873655ab136c104ce4c8fcc562acac691ab8efe35e8bf6e61cecfe9f7fd0de73e52f42f60df591f40c8ae011b8560fd2dd845c9f93eb7919ac3eb7f8a344cdf9f85724eae9a44a1c104e6d9e299c4bcd59df9dd269a35b21389c5c27c9086bfc290630fdb06422f1556b22d87098dcad2ff3ad7ef4113842e869b7c68d815b81b094720506d5e040d5df552b1c668f3e72e1544c0589bd89c2a73c03cf9507a5ab3673cad0036b1fe5d8f4b4adacf6d07f9a265a156a8da31dfd4f0de0e727f538cc3d215004375f8d57d744a5615b6e105fdd5f43b9cf8cd7b86a7951c74e84fee37e6790940f85873aba76dea90fa9ce556b946aa2f3b7609c725ae5efce8448249ccff6d3fb3c2ce449b1511a0c37adf93d9878e8f8b1a691a0fa8a0971fe0d4ac87765006af3ce48378c4da894c728dcf24670ef709bddba6739af06dcb5810e3600577e759d673fa579af1b9f6e665d3875a7655ef169186cdab63d372f21cc431bcf2666dc2d0bdc8a07bbc02f07c6e921ff9b997745b16ee0b620b9278f96e029b8b5a678e2df619a3dbf7f7a17c1c5882227e1ee652ec1a0377774da8b7c7087ab5abd23ca027b541248c78e2b02ac15affa38563472297e2838459b44a3849bedb26359a49f82ca531b4bb5a48abf3a5561b8b806f0cead5a5b24122933675d6d51d16f3cfdbb91fd981f5eb129cb77ecfe35828b39a4dab9257120237b60be18541a4a7bf175f2173548e2a31ff019db09b8346c92b9f6f5aae64f50f51c4380d34f8f573c8d94314ebee2ef833a43738224dfe3db256f09548627d97e48db3d9175451e3a4310c0c5ca8df9443c2d7ff2908878258f79b3148da9246771e87c99ebe2e466c2afb0e736c3ee1e5a28e92eebf66ae611a168eea0c2da2bdaf3066d5fe16b953bb9a364719f6fbd20123491f929ddc3e7d474372e602434b52a1302919bb31fb3e63d776d2e4b8b70ccb1212f9c5054e29cfad7886ee9ae0625e164c683af24bfaf2955c610707d0e081dc104abe519e4b1cb1972df6d278f24410b020757acff738b0d31bfd512da8246d5fe22fece9ba67d10fd4eca6cafcefcd5f261ab9758d7a991e2211e8cde42cdd444b8ce82f5fceb7ea057eb5248a74bdb4866e5e926bf848773dc038fe6a7e5d5d76bd342570b8db13c143d9a39903d8548921b784596d5735dbc7c24e4489ece3d56c50f84ac1b8a93802be8988610ca59dc75f2d4d7bf6c9719555dd7h");

			Integer g("0x2");

			Integer q("0x5b9d341f46c3e602ca7e1873c7cddedd211f922eefa00842436dfb5e8ff68d3c7afa439b3bb84df468b160e41c614b75e0b1eb1d68d7c2b61af5f14bf6076bb375fa5bff04ef68cf852ea5d03cc39b2ad589b6082672647e62b15656348d5c77f1af45fb730e767f4fbfe86f39f297a17b06fac8fa06457008dc2b07e96ec22e4fc9f5bc8cd61f5bfc51a266fcfc2b927574d2250e082736cf14ce25e6acefcee934d1ad909c4e2e13e48435fe1483187ed8321178aab5916c384c6e5697f9d6bf7a089c217434dbe346c0adc0d84a3902836af0206aefaa958e33479f3970aa2602c4dec4e1539e01e7ca83d2d59b39e56801b58ff2ec7a5a56d67b683fcd132d0ab546d18efea786f07393fa9c661e90a8021bafc6abeba252b0adb7082feeafa1dce7c66bdc353ca8e3a7427f71bf33c84a07c2c39d5d3b6f5487d4e72ab5ca355179dbb04e392d72f7e74224124e67fb69fd9e167224d8a88d061bd6fc9ecc3c747c58d348d07d4504b8ff06a5643bb2803579e7241bc626d44a63946e79233877b84deedd339cd7836e5ac0871b002bbf3aceb39fd2bcd78dcfb7332e9c3ad3b2af78b48c366d5b1e9b9790e6218de793336e1685ee4503dde01783e37490ffcdccbba2d8b7705b105c93c7cb7014dc5ad33c716fb0cd1edfbfbd0be0e2c41113f0f7329760d01bbbba6d45be3843d5ad5e91e5013daa092463c71581560ad7fd1c2b1a3914bf141c22cda251c24df6d931acd24fc165298da5dad2455f9d2ab0dc5c03786756ad2d92091499b3aeb6a8e8b79e7eddc8fecc0faf5894e5bbf67f1ac1459cd26d5c92b89011bdb05f0c2a0d253df8baf90b9aa471518ff80ced84dc1a36495cfb7ad57327a87a8e21c069a7c7ab9e46ca18a75f7177c19d21b9c1126ff1ed92b784aa4313ecbf246d9ec8baa28f1d21886062e546fca21e16bff948443c12c7bcd98a46d49233b8f43e4cf5f172336157d8739b61f70f2d14749775fb357308d0b47750616d15ed798336aff0b5ca9ddcd1b238cfb7de90091a48fc94eee1f3ea3a1b9730121a5a95098148cdd98fd9f31ebbb69725c5b866589097ce282a714e7d6bc43774d70312f0b26341d7925fd794aae308383e87040ee08255f28cf258e58cb96fb693c79220858103abd67fb9c58698dfea896d41236aff117f674dd33e887ea7653657e77e6af930d5cbac6bd4c8f1108f466f2166ea225c67417afe75bf502bf5a92453a5eda43372f4935fc243b9ee01c7f353f2eaebb5e9a12b85c6d89e0a1ecd1cc81ec2a4490dbc22cb6ab9aede3e1272244f671eab6287c2560dc549c015f44c4308652cee3af96a6bdfb64b8caaaeebh");

			dh.AccessGroupParameters().Initialize(p, q, g);	

		// } else if (bits == 15360){

		} else {
			dh.AccessGroupParameters().GenerateRandomWithKeySize(rnd, bits);	
		}

		if(!dh.GetGroupParameters().ValidateGroup(rnd, 3))
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

		SecByteBlock priv1(dh.PrivateKeyLength());
		SecByteBlock pub1(dh.PublicKeyLength());
		SecByteBlock priv2(dh.PrivateKeyLength());
		SecByteBlock pub2(dh.PublicKeyLength());
		dh.GenerateKeyPair(rnd, priv1, pub1);
		dh.GenerateKeyPair(rnd, priv2, pub2);

		SecByteBlock sharedA(dh.AgreedValueLength()), sharedB(dh.AgreedValueLength());

		if(!dh.Agree(sharedA, priv1, pub2))
			throw runtime_error("Failed to reach shared secret (1A)");

		if(!dh.Agree(sharedB, priv2, pub1))
			throw runtime_error("Failed to reach shared secret (B)");

		//cout << "Generated shared secret!" << endl;

		count = dh.AgreedValueLength();
		if(!count || 0 != memcmp(sharedA.BytePtr(), sharedB.BytePtr(), count))
			throw runtime_error("Failed to reach shared secret");

		Integer a,b;
	    a.Decode(sharedA.BytePtr(), sharedA.SizeInBytes());
	    //cout << "(A): " << std::hex << a << endl;

	    b.Decode(sharedB.BytePtr(), sharedB.SizeInBytes());
		//cout << "Shared secret (B): " << std::hex << b << endl;
	}

	catch(const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
	}

	catch(const std::exception& e)
	{
		cerr << e.what() << endl;
	}

	return 0;
}

