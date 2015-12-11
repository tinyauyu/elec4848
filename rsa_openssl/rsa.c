#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <sys/resource.h>

#define PUB_EXP     65537
#define REPEAT		1000
//#define PRINT_KEYS
//#define WRITE_TO_FILE

int isKeyExists(const char * filepath){
	FILE * file;
	if (file = fopen(filepath, "r")){
		fclose(file);
		return 1;
	} else {
		return 0;
	}

}

void saveKeyToFile(const char *data, const char *filepath) {
    FILE *fp = fopen(filepath, "ab");
    if (fp != NULL)
    {
        fputs(data, fp);
        fclose(fp);
    }
}

RSA * createRSA(FILE* fp, int isPublicKey) {
	RSA *rsa= NULL;
	if(isPublicKey){
		rsa = PEM_read_RSAPublicKey(fp, &rsa, NULL, NULL);
	} else {
		rsa = PEM_read_RSAPrivateKey(fp, &rsa, NULL, NULL);
	}

	if(rsa == NULL) {
	    printf( "***** Failed to create RSA *****\n");
	    printf(">> isPublicKey = %d\n",isPublicKey);
	}

	return rsa;
}


int main(int argc, char **argv) {
	
	int    key_length;         // Length of key to be generated
	char*  key_length_s;

	if(argc>1){
		key_length = atoi(argv[1]);
		key_length_s = argv[1];
	} else {
		key_length = 2048;
		key_length_s = "2048";
	}

    size_t pri_len;					// Length of private key
    size_t pub_len;					// Length of public key
    //char   *pri_key;				// Private key
    //char   *pub_key;				// Public key
    char   msg[key_length/8];		// Message to encrypt
    char   *encrypt = NULL;			// Encrypted message
    char   *decrypt = NULL;			// Decrypted message
    char   *err;					// Buffer for any error messages
    RSA    *keypair, *privateKey, *publicKey;

    struct timeval stop, start;		// start and stop time
    //struct rusage stop_r, start_r;

    int i;

    // define file name here
    char* publicKeyFilePath = malloc(sizeof(char)*(13+strlen(key_length_s)));
    memset(publicKeyFilePath, 0, 13+strlen(argv[1]));
    strcat(publicKeyFilePath, "RSA-pub-");
    strcat(publicKeyFilePath, argv[1]);
    strcat(publicKeyFilePath, ".pem\0");

    char* privateKeyFilePath = malloc(sizeof(char)*(13+strlen(key_length_s)));
    memset(privateKeyFilePath, 0, 13+strlen(argv[1]));
    strcat(privateKeyFilePath, "RSA-pri-");
    strcat(privateKeyFilePath, argv[1]);
    strcat(privateKeyFilePath, ".pem\0");

    /*** Generate key pair ***/
    if(!isKeyExists(publicKeyFilePath) || !isKeyExists(privateKeyFilePath)){
    	//printf("Key file not exists!\nGenerating RSA (%d bits) keypair...\n", key_length);
	    fflush(stdout);
	    //gettimeofday(&start, NULL);
	    keypair = RSA_generate_key(key_length, PUB_EXP, NULL, NULL);
	    //gettimeofday(&stop, NULL);
	    //printf("Key Generation cost: (utime) %lu μs\n", stop_r.ru_utime.tv_usec - start_r.ru_utime.tv_usec);

	    FILE *fp = fopen(privateKeyFilePath, "ab");
	    if (fp == NULL){ printf("Cannot open private key file."); exit(2);}
	    PEM_write_RSAPrivateKey(fp, keypair, NULL, NULL, 0, NULL, NULL);
	    fclose(fp);

	    fp = fopen(publicKeyFilePath, "ab");
	    if (fp == NULL){ printf("Cannot open public key file."); exit(2);}
	    PEM_write_RSAPublicKey(fp, keypair);
	    fclose(fp);
    }

    /*** Load Key ***/

    FILE * pFile;
	size_t result;

	pFile = fopen ( publicKeyFilePath , "rb" );
	if (pFile==NULL) {fputs ("File error",stderr); exit (1);}
	publicKey = createRSA(pFile,1);
	fclose (pFile);

	pFile = fopen ( privateKeyFilePath , "rb" );
	if (pFile==NULL) {fputs ("File error",stderr); exit (1);}
	privateKey = createRSA(pFile,0);
	fclose (pFile);


    /*** Encryption Part ***/

    // Get the message to encrypt
    if(argc>2){
    	strcpy(msg, argv[2]);
    } else {
    	printf("Message to encrypt: ");
    	fgets(msg, key_length-1, stdin);
    	msg[strlen(msg)-1] = '\0';

    }

    // Encrypt the message
    
    int encrypt_len;
    err = malloc(130);


    if(argc>=3){
    	if(strcmp(argv[3],"private") == 0){
    		encrypt = malloc(RSA_size(privateKey));  //<<<may be the problem for not using RSA_size()
    		//printf("private: ");
    		gettimeofday(&start, NULL);
    		
		
		    if((encrypt_len = RSA_private_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
		                                         privateKey, RSA_PKCS1_PADDING)) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error encrypting message: %s\n", err);
		        goto free_stuff;
		    }
			
		    gettimeofday(&stop, NULL);
		
    	} else {
    		//printf("public: ");
    		default_public_encrypt:
    		encrypt = malloc(RSA_size(publicKey));  //<<<may be the problem for not using RSA_size()
    		gettimeofday(&start, NULL);
    		
		    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
		                                         publicKey, RSA_PKCS1_PADDING)) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error encrypting message: %s\n", err);
		        goto free_stuff;
		    }
			    
			gettimeofday(&stop, NULL);

    	}
    } else {
    	printf("default");
    	goto default_public_encrypt;
    }


    // print Encryption time
    printf("%ld ", (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000);

    #ifdef WRITE_TO_FILE
    // Write the encrypted message to a file
        FILE *out = fopen("out.bin", "w");
        fwrite(encrypt, sizeof(*encrypt),  encrypt_len, out);
        fclose(out);
        printf("Encrypted message written to file.\n");
        free(encrypt);
        encrypt = NULL;

        // Read it back
        printf("Reading back encrypted message and attempting decryption...\n");
        encrypt = malloc(encrypt_len);
        out = fopen("out.bin", "r");
        fread(encrypt, sizeof(*encrypt), encrypt_len, out);
        fclose(out);
    #endif

    // Decrypt it
    decrypt = malloc(encrypt_len);

    if(argc>3){
    	if(strcmp(argv[3],"private") == 0){

			gettimeofday(&start, NULL);
			
    		if(RSA_public_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
		                           publicKey, RSA_PKCS1_PADDING) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error decrypting message: %s\n", err);
		        goto free_stuff;
		    }
			
		    gettimeofday(&stop, NULL);
		/*
		} else if(argv[3]=="sign"){
			gettimeofday(&start, NULL);
			// RSA_sign
		    signlen = 0;
		    if(RSA_verify(NID_md5, (unsigned char*) msg, strlen(msg), sign, &signlen, keypair) != 1) { 
            	printf("RSA_verify error.");
        	}
        	gettimeofday(&stop, NULL);
		*/
    	} else {
    		default_private_decrypt:

    		gettimeofday(&start, NULL);
    		
    		if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
		                           privateKey, RSA_PKCS1_PADDING) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error decrypting message: %s\n", err);
		        goto free_stuff;
		    }
			
			gettimeofday(&stop, NULL);

    	}
    } else {
    	goto default_private_decrypt;
    }

    //printf("Decrypted message: %s\n", decrypt);
    if(strcmp(decrypt,msg)!=0){
    	printf("*** Decrypted message incorrect! ***\n");
    	printf("Decrypted message: %s\n", decrypt);
    }

    printf("%ld\n", (stop.tv_usec - start.tv_usec) + (stop.tv_sec - start.tv_sec)*1000000);

    //printf("Encryption cost: (wall) %lu μs\n", stop.tv_usec - start.tv_usec);
    //tv_sec + (tv)->tv_usec / 1000000.00
    

    /*
    // Encrypt the message
    encrypt = malloc(RSA_size(keypair));
    int encrypt_len;
    err = malloc(130);

    if(argc>3){
    	if(argv[3]=="private"){
    		gettimeofday(&start, NULL);
		    if((encrypt_len = RSA_private_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
		                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error encrypting message: %s\n", err);
		        goto free_stuff;
		    }
		    gettimeofday(&stop, NULL);

    	} else {
    		default_public_encrypt:
    		gettimeofday(&start, NULL);
		    if((encrypt_len = RSA_public_encrypt(strlen(msg)+1, (unsigned char*)msg, (unsigned char*)encrypt,
		                                         keypair, RSA_PKCS1_OAEP_PADDING)) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error encrypting message: %s\n", err);
		        goto free_stuff;
		    }
		    gettimeofday(&stop, NULL);

    	}
    } else {
    	goto default_public_encrypt;
    }
    

    //printf("Encryption cost: (wall) %lu μs\n", stop.tv_usec - start.tv_usec);
    printf("%lu\n", stop.tv_usec - start.tv_usec);

    #ifdef WRITE_TO_FILE
    // Write the encrypted message to a file
        FILE *out = fopen("out.bin", "w");
        fwrite(encrypt, sizeof(*encrypt),  RSA_size(keypair), out);
        fclose(out);
        printf("Encrypted message written to file.\n");
        free(encrypt);
        encrypt = NULL;

        // Read it back
        printf("Reading back encrypted message and attempting decryption...\n");
        encrypt = malloc(RSA_size(keypair));
        out = fopen("out.bin", "r");
        fread(encrypt, sizeof(*encrypt), RSA_size(keypair), out);
        fclose(out);
    #endif

    // Decrypt it
    decrypt = malloc(encrypt_len);

    if(argc>3){
    	if(argv[3]=="private"){
    		if(RSA_public_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
		                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error decrypting message: %s\n", err);
		        goto free_stuff;
		    }

    	} else {
    		default_private_decrypt:
    		if(RSA_private_decrypt(encrypt_len, (unsigned char*)encrypt, (unsigned char*)decrypt,
		                           keypair, RSA_PKCS1_OAEP_PADDING) == -1) {
		        ERR_load_crypto_strings();
		        ERR_error_string(ERR_get_error(), err);
		        fprintf(stderr, "Error decrypting message: %s\n", err);
		        goto free_stuff;
		    }

    	}
    } else {
    	goto default_private_decrypt;
    }

    //printf("Decrypted message: %s\n", decrypt);
    if(strcmp(decrypt,msg)!=0){
    	printf("*** Decrypted message incorrect! ***\n");
    	printf("Decrypted message: %s\n", decrypt);
    }
	*/

    free_stuff:
    RSA_free(keypair);
    RSA_free(publicKey);
    RSA_free(privateKey);
    
    free(encrypt);
    free(decrypt);
    free(err);
    free(publicKeyFilePath);
    free(privateKeyFilePath);

    return 0;
}