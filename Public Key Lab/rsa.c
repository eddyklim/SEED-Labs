// Eduard Klimenko
// Textbook RSA (without padding). 
#include <stdio.h>
#include <openssl/bn.h>

int main (){
  BN_CTX *ctx = BN_CTX_new();         // struct used to hold BIGNUM
  BIGNUM *one = BN_new();	      // the number 1
  BIGNUM *p = BN_new();               // p
  BIGNUM *p_minus_1 = BN_new();       // p-1
  BIGNUM *q = BN_new();               // q
  BIGNUM *q_minus_1 = BN_new();       // q-1
  BIGNUM *n = BN_new();               // n = p*q
  BIGNUM *e = BN_new();               // e
  BIGNUM *e_mult_inverse = BN_new();  // e^-1
  BIGNUM *phi = BN_new();             // phi = (p-1)*(q-1)
  BIGNUM *d = BN_new();               // d
  BIGNUM *m_in = BN_new();            // message to be encrypted
  BIGNUM *m_out = BN_new();           // message produced from decryption
  BIGNUM *c = BN_new();               // ciphertext

  // the number 1
  BN_dec2bn(&one,"1");
  
  // should be randomly generated
  BN_dec2bn(&p,"7"); 
  BN_dec2bn(&q,"11");
  BN_dec2bn(&e,"7");
  
  // message
  BN_dec2bn(&m_in,"25");
  
  // key generation:
  // n = p*q
  BN_mul(n, p, q, ctx);

  // p-1 and q-1
  BN_sub(p_minus_1, p, one);
  BN_sub(q_minus_1, q, one);

  // phi(n) = (p-1)*(q-1)
  BN_mul(phi, p_minus_1, q_minus_1, ctx);

  // e*x+phi(n)*y=1
  BN_mod_inverse(e_mult_inverse, e, phi, ctx);  
  
  // d = eˆ-1 mod phi(n)
  BN_mod(d, e_mult_inverse, phi, ctx);

  // print out p, q, e, n, d, m
  printf("p = %s, q = %s\n\n", BN_bn2dec(p), BN_bn2dec(q));
  printf("Public Key: e = %s, n = %s\nPrivate Key: d = %s\n\n",BN_bn2dec(e), BN_bn2dec(n), BN_bn2dec(d));
  printf("m = %s\n",BN_bn2dec(m_in));

  // encryption:
  // c = m^e mod n  
  BN_mod_exp(c, m_in, e, n, ctx); 
  printf("c = %s\n\n",BN_bn2dec(c));

  // decryption:
  // m = c^d mod n
  BN_mod_exp(m_out, c, d, n, ctx); 
  printf("c decrypted = %s\n",BN_bn2dec(m_out));

  // free struct
  BN_CTX_free(ctx);

  return 0;
}