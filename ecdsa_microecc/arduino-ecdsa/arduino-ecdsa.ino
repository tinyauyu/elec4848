#include "sha256.h"

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
        //Serial.print("0x");
        if((unsigned)vli[i]<16){
          Serial.print(0,HEX);
        }
        Serial.print((unsigned)vli[i],HEX);
        //Serial.print(',');
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
int iteration, c;
long totalSign, totalVerify;
void setup() {
  Serial.begin(9600);
  Serial.println("Testing ecdsa");
  //uECC_set_rng(&RNG);
  uECC_set_rng(&RNG);
  init_curve();

//  iteration = 0;
  c = 0;

  pinMode(7, OUTPUT);
  digitalWrite(7,LOW);
  pinMode(13, OUTPUT);
  digitalWrite(13, HIGH);
  delay(15000);
  digitalWrite(13, LOW);
}

void loop() {
  //Serial.print(iteration);
  //Serial.print("->");
  //Serial.print(totalTime);
  //Serial.print("->");
  if(iteration > 1){
    digitalWrite(7,LOW);
    c++;
    if(c>4){c=5; digitalWrite(13,HIGH); digitalWrite(7,LOW); return;}
    iteration = 0;
    Serial.print("done curve ");
    Serial.println(c);
    Serial.print("totalSign = ");
    Serial.println(totalSign);
    Serial.print("totalVerify = ");
    Serial.println(totalVerify);
    totalSign = 0;
    totalVerify = 0;
     delay(500);
  }

  if(c>4){c=5; digitalWrite(13,HIGH); digitalWrite(7,LOW); return;}
  
  const int pubkey_size = uECC_curve_public_key_size(curves[c]);
  const int prikey_size = uECC_curve_private_key_size(curves[c]);
  //Serial.print("pub key size = ");
  //Serial.println(pubkey_size);
  uint8_t privatekey[prikey_size];
  uint8_t publickey[pubkey_size];
  
  char message[] = "Sld48xaGrmMGkX6UJCuSU4Q0j33QPtQt0NUNmPfoMyIEJa2ioVGtohV6o2S1EfNRiv31VTuoDnWS3iyT9LSYvlRyxxjPPnqTd3nl7Gl5JrGdqifh4RXJNx3AJjj8tByj";
  int message_len = 128;

  uint8_t *hash;
  int hash_len = 32;
  Sha256.init();
  Sha256.print(message);
  hash = Sha256.result();
  
  uint8_t sig[64] = {0};

 // Serial.print("Message: ");
  //vli_print((uint8_t*)hash, hash_len);
  

  //Serial.println("Generate keys...");
  //uint8_t publickey[] = {0x3E,0x5D,0xAC,0x6B,0x35,0x2D,0x67,0xC0,0x9F,0x8C,0x11,0x1B,0x57,0xA6,0x5A,0xC3,0xFF,0xAD,0x08,0xB9,0x0B,0x89,0x71,0x1B,0x72,0xA4,0xA0,0xEF,0x8E,0x84,0xF4,0x7D,0xEF,0xD9,0xCD,0x12,0xA3,0xF9,0x11,0x89,0xEC,0xDF,0xFE,0x6A,0x88,0x08,0xB6,0xB4,0x2C,0x3C,0x36,0xF2,0x24,0x89,0x8E,0xB7,0xB4,0x29,0xD4,0xFB,0x1D,0x1F,0x1F,0xB7};
  //uint8_t privatekey[] = {0xE1,0x2F,0xB7,0x75,0x65,0xA6,0xC2,0x09,0xB1,0xD9,0xF6,0xC3,0xF6,0x54,0x6C,0xF5,0xAE,0xFE,0x06,0x66,0xD3,0x35,0x75,0x04,0xA7,0xB9,0x8F,0x78,0xBD,0xE3,0xB7,0xEC};
  
  
  if (!uECC_make_key(publickey, privatekey, curves[c])) {
      Serial.println("uECC_make_key() failed\n");
      return;
  }
  
  
  
  //Serial.print("public key: ");
  //int pub_en_len = (int) base64_enc_len(pubkey_size);
  //char pub_en[pub_en_len];
  //base64_encode(pub_en, (char*) publickey, pub_en_len);
  //Serial.println(pub_en);
  //vli_print(publickey, pubkey_size);
  
  //Serial.print("private key: ");
  //int pri_en_len = (int) base64_enc_len(prikey_size);
  //char pri_en[pri_en_len];
  //base64_encode(pri_en, (char*) privatekey, pri_en_len);
  //Serial.println(pri_en);
  //vli_print(privatekey, prikey_size);

  //Serial.println("Signing message...");
  digitalWrite(7,HIGH); 
  unsigned long a = millis();
  Sha256.init();
  Sha256.print(message);
  hash = Sha256.result();
  if (!uECC_sign(privatekey,(uint8_t*) hash, hash_len, sig, curves[c])) {
      Serial.println("uECC_sign() failed");
      return;
  }
  unsigned long b = millis();
  //Serial.print(b-a);
  totalSign = totalSign + (b-a);
  //Serial.print("sign: ");
  //int sig_en_len = (int) base64_enc_len(sizeof(sig));
  //char sig_en[sig_en_len];
  //base64_encode(sig_en, (char*) sig, sig_en_len);
  //Serial.println(sig_en);
  //vli_print(sig, pubkey_size);
  a = millis();
  Sha256.init();
  Sha256.print(message);
  hash = Sha256.result();
  if (!uECC_verify(publickey, (uint8_t*) hash, hash_len, sig, curves[c])) {
      Serial.println("uECC_verify() failed");
      return;
  }
  digitalWrite(7,LOW); 
  b = millis();
  //Serial.print(" ");
  //Serial.println(b-a);
  totalVerify = totalVerify + (b-a);
 // Serial.println("Verified!");
 iteration++;
}

