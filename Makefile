all: ecc_cryptopp rsa_cryptopp rsa_openssl

ecc_cryptopp:
	cd ecc_cryptopp && $(MAKE) all

rsa_cryptopp:
	cd rsa_cryptopp && $(MAKE) all

rsa_openssl:
	cd rsa_openssl && $(MAKE) all

benchmark: all
	cd ecc_cryptopp && $(MAKE) benchmark
	cd rsa_cryptopp && $(MAKE) benchmark
	cd rsa_openssl && $(MAKE) benchmark

clean:
	cd ecc_cryptopp && $(MAKE) clean
	cd rsa_cryptopp && $(MAKE) clean
	cd rsa_openssl && $(MAKE) clean