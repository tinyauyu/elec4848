#include <uECC_vli.h>
#include <types.h>
#include <uECC.h>

#include <Base64.h>

extern "C" {

static int RNG(uint8_t *dest, unsigned size) {
  // Use the least-significant bits from the ADC for an unconnected pin (or connected to a source of 
  // random noise). This can take a long time to generate random data if the result of analogRead(0) 
  // doesn't change very frequently.
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
      int init = analogRead(0);
      int count = 0;
      while (analogRead(0) == init) {
        ++count;
      }
      
      if (count == 0) {
         val = (val << 1) | (init & 0x01);
      } else {
         val = (val << 1) | (count & 0x01);
      }
    }
    *dest = val;
    ++dest;
    --size;
  }
  // NOTE: it would be a good idea to hash the resulting random data using SHA-256 or similar.
  return 1;
}

}  // extern "C"

void vli_print(uint8_t *vli, unsigned int size) {
    for(unsigned i=0; i<size; ++i) {
        Serial.print((unsigned)vli[i],HEX);
    }
    Serial.println();
}

/*** Curve Definition ***/
const struct uECC_Curve_t * curves[5];
int num_curves = 0;

void init_curve(){
  #if uECC_SUPPORTS_secp160r1
    curves[num_curves++] = uECC_secp160r1();
  #endif
  #if uECC_SUPPORTS_secp192r1
    curves[num_curves++] = uECC_secp192r1();
  #endif
  #if uECC_SUPPORTS_secp224r1
    curves[num_curves++] = uECC_secp224r1();
  #endif
  #if uECC_SUPPORTS_secp256r1
    curves[num_curves++] = uECC_secp256r1();
  #endif
  #if uECC_SUPPORTS_secp256k1
    curves[num_curves++] = uECC_secp256k1();
  #endif
}
/************************/

void setup() {
  Serial.begin(9600);
  Serial.println("Testing ecdsa");
  uECC_set_rng(&RNG);
  init_curve();
}

void loop() {
  int c = 2;   // using secp256r1
  int pubkey_size = uECC_curve_public_key_size(curves[c]);
  int prikey_size = uECC_curve_private_key_size(curves[c]);
  Serial.print("pub key size = ");
  Serial.println(pubkey_size);
  uint8_t privatekey[32] = {0};
  uint8_t publickey[64] = {0};
  char hash[] = "This is an apple!";
  uint8_t sig[64] = {0};
  

  Serial.println("Generate keys...");
  if (!uECC_make_key(publickey, privatekey, curves[c])) {
      Serial.println("uECC_make_key() failed\n");
      return;
  }
  
  Serial.print("public key: ");
  int pub_en_len = (int) base64_enc_len(pubkey_size);
  char pub_en[pub_en_len];
  base64_encode(pub_en, (char*) publickey, pub_en_len);
  Serial.println(pub_en);
  
  Serial.print("private key: ");
  int pri_en_len = (int) base64_enc_len(prikey_size);
  char pri_en[pri_en_len];
  base64_encode(pri_en, (char*) privatekey, pri_en_len);
  Serial.println(pri_en);

  Serial.println("Signing message...");
  if (!uECC_sign(privatekey,(uint8_t*) hash, sizeof(hash), sig, curves[c])) {
      Serial.println("uECC_sign() failed");
      return;
  }
  Serial.print("sign: ");
  int sig_en_len = (int) base64_enc_len(sizeof(sig));
  char sig_en[sig_en_len];
  base64_encode(sig_en, (char*) sig, sig_en_len);
  Serial.println(sig_en);

  if (!uECC_verify(publickey, (uint8_t*) hash, sizeof(hash), sig, curves[c])) {
      Serial.println("uECC_verify() failed");
      return;
  }
  Serial.println("Verified!");
}

