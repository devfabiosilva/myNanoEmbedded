/*
 * AUTHOR: Fábio Pereira da Silva
 * YEAR: 2019
 * LICENSE: MIT
 * EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
 *
 * Main file of Nano cryptocurrency P2PoW/DPoW support
 *
 */

//Wed Sep 18 2019 21:59:01 -03

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>

#ifndef F_ESP32
 #include <pthread.h>
#endif

#include "f_nano_crypto_util.h"
#include "f_add_bn_288_le.h"

#ifdef F_XTENSA

 #ifndef F_ESP32

  #define F_ESP32

 #endif

#endif

#ifdef F_ESP32

 #include "esp_task_wdt.h"
 #include "esp_system.h"

#endif

#include "mbedtls/bignum.h"

#ifndef F_ESP32

typedef struct f_local_pow_thread_t {

   int err;
   int flag;
   uint64_t threshold;
   uint64_t pow;
   unsigned char *hash;

} LOCAL_POW_THREAD;

static pthread_mutex_t thr_mtx;
#define F_ERR_THREAD_MALLOC (int)12680
#define F_ERR_THREAD_SODIUM_INIT (int)12681
#define F_FLAG_THREAD_WINNER (int)12700

#endif

static const char *__dictionary_path=BIP39_DICTIONARY;

inline void f_set_dictionary_path(const char *path) { (path)?(__dictionary_path=path):(__dictionary_path=BIP39_DICTIONARY); }
inline char *f_get_dictionary_path(void) { return (char *)__dictionary_path; }

double to_multiplier(uint64_t difficulty, uint64_t base_difficulty) { return ((double)-base_difficulty)/((double)-difficulty); }

uint64_t from_multiplier(double multiplier, uint64_t base_difficulty) { return (uint64_t)(-(uint64_t)((double)(-base_difficulty)/multiplier)); }
/*
#ifdef F_ESP32
int IRAM_ATTR f_reverse(unsigned char *val, size_t val_sz)
#else
int f_reverse(unsigned char *val, size_t val_sz)
#endif
{
   unsigned char *buf, *buf_tmp;
   size_t sz_tmp;

   if (!val_sz)
      return 1;

   if (!(buf=malloc(val_sz)))
      return 2;

   buf_tmp=buf;
   sz_tmp=val_sz;

   for (;sz_tmp;)
      *(buf_tmp++)=val[--sz_tmp];

   memcpy(val, buf, val_sz);
   memset(buf, 0, val_sz);
   free(buf);

   return 0;
}
*/
#define LIST_STR_WALLET (size_t)56
#ifdef F_ESP32
static int IRAM_ATTR str_wallet_to_alphabet_index(uint8_t *list, char *str_wallet, size_t str_sz)
#else
static int str_wallet_to_alphabet_index(uint8_t *list, char *str_wallet, size_t str_sz)
#endif
{
   int err;
   int i, j;
   extern const char alphabet[] asm("_binary_alphabet_dat_start");

   for (j=0;j<str_sz;j++) {

      err=32;

      for (i=0;i<32;i++)
         if (alphabet[i]==str_wallet[j]) {
            err=0;
            list[j]=(uint8_t)i;
            break;
         }

      if (err)
         return err;

   }

   return err;

}

#ifdef F_ESP32
int IRAM_ATTR nano_base_32_2_hex(uint8_t *res, char *str_wallet)
#else
int nano_base_32_2_hex(uint8_t *res, char *str_wallet)
#endif
{
   int i, j;
   uint8_t a, b, c;
   uint8_t list_str_wallet[LIST_STR_WALLET];
   uint8_t buf[5];
   uint8_t *fp;
   F_ADD_288 displace;

   if ((i=(int)(strnlen(str_wallet, STR_NANO_SZ)))==STR_NANO_SZ)
      return 41;

   if (i<64)
      return 40;

   if (memcmp(str_wallet, NANO_PREFIX, sizeof(NANO_PREFIX)-1)) {

      if (memcmp(str_wallet, XRB_PREFIX, sizeof(XRB_PREFIX)-1))
         return 39;

      if (i^64)
         return 38;

      str_wallet+=4;

   } else {

      if (i^65)
         return 37;

      str_wallet+=5;

   }

   if (str_wallet_to_alphabet_index(list_str_wallet, str_wallet, 52))
      return 17;

   i=0;

   list_str_wallet[52]=0;

   fp=res;

   for (j=0;j<6;j++) {

      a=list_str_wallet[i++];
      b=list_str_wallet[i++];
      *(res++)=((a<<3)|(b>>2));

      a=list_str_wallet[i++];
      c=list_str_wallet[i++];
      *(res++)=((b<<6)|(a<<1)|(c>>4));

      a=list_str_wallet[i++];
      *(res++)=((c<<4)|(a>>1));

      b=list_str_wallet[i++];
      c=list_str_wallet[i++];

      *(res++)=((a<<7)|(b<<2)|(c>>3));

      a=list_str_wallet[i++];
      *(res++)=(a|(c<<5));

   }

   a=list_str_wallet[i++];
   b=list_str_wallet[i++];
   *(res++)=((a<<3)|(b>>2));

   a=list_str_wallet[i++];
   c=list_str_wallet[i++];
   *(res++)=((b<<6)|(a<<1)|(c>>4));

   a=list_str_wallet[i];
   *(res++)=((c<<4)|(a>>1));

   if (str_wallet_to_alphabet_index(list_str_wallet, str_wallet+52, 8))
      return 19;

   i=0;

   a=list_str_wallet[i++];
   b=list_str_wallet[i++];
   *(res++)=((a<<3)|(b>>2));

   a=list_str_wallet[i++];
   c=list_str_wallet[i++];
   *(res++)=((b<<6)|(a<<1)|(c>>4));

   a=list_str_wallet[i++];
   *(res++)=((c<<4)|(a>>1));

   b=list_str_wallet[i++];
   c=list_str_wallet[i++];

   *(res++)=((a<<7)|(b<<2)|(c>>3));

   a=list_str_wallet[i];
   *res=(a|(c<<5));

   if (f_reverse((unsigned char *)fp+33, 5))
      return 20;

   if (f_reverse((unsigned char *)fp, 33))
      return 21;

   memset(displace, 0, sizeof(displace));

   memcpy(displace, fp, 33);

   f_add_bn_288_le(displace, displace, displace, NULL, 0);
   f_add_bn_288_le(displace, displace, displace, NULL, 0);
   f_add_bn_288_le(displace, displace, displace, NULL, 0);
   f_add_bn_288_le(displace, displace, displace, NULL, 0);

   if (f_reverse((unsigned char *)displace, sizeof(displace)))
      return 22; 

   memcpy(fp, ((uint8_t *)displace)+3, 32);

   if (crypto_generichash((unsigned char *)buf, 5, fp, 32, NULL, 0))
      return 24;

   if (memcmp(fp+33, buf, 5))
      return ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM;

   return 0;
}

#define F_SIGN_BUF_SZ (size_t)(sizeof(crypto_generichash_state)+64+32+sizeof(ge25519_p3)+sizeof(ge25519_p2))
#ifdef F_ESP32
static int IRAM_ATTR f_crypto_sign_ed25519_verify_detached(const unsigned char *sig, const unsigned char *m, size_t mlen, const unsigned char *pk)
{

   int err, i;
   unsigned char d = 0;
   crypto_generichash_state *hs; //
   unsigned char *h; //64
   unsigned char *rcheck; //[32];
   ge_p3 *A;
   ge_p2 *R;

   uint8_t *buf;

   if (!(buf=malloc(F_SIGN_BUF_SZ)))
      return 12520;

   hs=(crypto_generichash_state *)buf;
   h=(unsigned char *)(buf+sizeof(crypto_generichash_state));
   rcheck=(unsigned char *)(h+64);
   A=(ge_p3 *)(rcheck+32);
   R=(ge_p2 *)(((uint8_t *)A)+sizeof(ge_p3));

   if (sig[63]&224) {

       err=12521;

       goto f_crypto_sign_ed25519_verify_detached_EXIT1;

   }

   if (ge_frombytes_negate_vartime(A, pk) != 0) {

      err=12522;

      goto f_crypto_sign_ed25519_verify_detached_EXIT1;

   }

   for (i=0;i<32;++i) {
      d|=pk[i];
   }

   if (d==0) {

      err=12523;

      goto f_crypto_sign_ed25519_verify_detached_EXIT1;

   }

   if (crypto_generichash_init(hs, NULL, 0, 64)) {
      err=12524;
      goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_update(hs, sig, 32)) {
      err=12525;
      goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_update(hs, pk, 32)) {
      err=12526;
      goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_update(hs, m, mlen)) {
      err=12527;
      goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_final(hs, h, 64)) {
      err=12528;
      goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   sc_reduce(h);

   ge_double_scalarmult_vartime(R, h, A, sig+32);
   ge_tobytes(rcheck, R);

   err=crypto_verify_32(rcheck, sig)|(-(rcheck==sig))|sodium_memcmp(sig, rcheck, 32);

f_crypto_sign_ed25519_verify_detached_EXIT1:
   memset(buf, 0, F_SIGN_BUF_SZ);
   free(buf);

   return err;

}
#else
static int f_crypto_sign_ed25519_verify_detached(const unsigned char *sig, const unsigned char *m, size_t mlen, const unsigned char *pk)
{
   int err;
   crypto_generichash_state *hs; //
   unsigned char *h; //64
   unsigned char *rcheck; //[32];
   ge25519_p3 *A;
   ge25519_p2 *R;

   uint8_t *buf;

   if (!(buf=malloc(F_SIGN_BUF_SZ)))
      return 12620;

   hs=(crypto_generichash_state *)buf;
   h=(unsigned char *)(buf+sizeof(crypto_generichash_state));
   rcheck=(unsigned char *)(h+64);
   A=(ge25519_p3 *)(rcheck+32);
   R=(ge25519_p2 *)(((uint8_t *)A)+sizeof(ge25519_p3));

   if ((sc25519_is_canonical(sig+32)==0)||(ge25519_has_small_order(sig)!=0)) {

       err=ERROR_25519_IS_NOT_CANONICAL_OR_HAS_NOT_SMALL_ORDER;

       goto f_crypto_sign_ed25519_verify_detached_EXIT1;

   }

   if ((ge25519_is_canonical(pk)==0)||(ge25519_has_small_order(pk)!=0)) {

       err=12622;

       goto f_crypto_sign_ed25519_verify_detached_EXIT1;

   }

   if (ge25519_frombytes_negate_vartime(A, pk)!=0) {

       err=12623;

       goto f_crypto_sign_ed25519_verify_detached_EXIT1;

   }

   if (crypto_generichash_init(hs, NULL, 0, 64)) {
       err=12624;
       goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_update(hs, sig, 32)) {
       err=12625;
       goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_update(hs, pk, 32)) {
       err=12626;
       goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_update(hs, m, mlen)) {
       err=12627;
       goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   if (crypto_generichash_final(hs, h, 64)) {
       err=12628;
       goto f_crypto_sign_ed25519_verify_detached_EXIT1;
   }

   sc25519_reduce(h);

   ge25519_double_scalarmult_vartime(R, h, A, sig+32);
   ge25519_tobytes(rcheck, R);

   err=crypto_verify_32(rcheck, sig)|(-(rcheck==sig))|sodium_memcmp(sig, rcheck, 32);

f_crypto_sign_ed25519_verify_detached_EXIT1:
   memset(buf, 0, F_SIGN_BUF_SZ);
   free(buf);

   return err;

}
#endif

#ifdef F_ESP32
static int IRAM_ATTR f_crypto_sign_ed25519_detached(unsigned char *sig, const unsigned char *m, size_t mlen, const unsigned char *sk)
#else
static int f_crypto_sign_ed25519_detached(unsigned char *sig, const unsigned char *m, size_t mlen, const unsigned char *sk)
#endif
{
   unsigned char az[64];
   unsigned char nonce[64];
   unsigned char hram[64];
   int err;
   ge_p3 *R;
   crypto_generichash_state *hs;

   R=malloc(sizeof(ge_p3));

   if (!R)
      return 6300;

   hs=malloc(sizeof(crypto_generichash_state));

   if (!hs) {
      err=6301;
      goto f_crypto_sign_ed25519_detached_EXIT1;
   }

   crypto_generichash(az, 64, sk, 32, NULL, 0);

   az[0]&=248;
   az[31]&=63;
   az[31]|=64;

   if (crypto_generichash_init(hs, NULL, 0, 64)) {
      err=6302;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   if (crypto_generichash_update(hs, az+32, 32)) {
      err=6303;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   if (crypto_generichash_update(hs, m, mlen)) {
      err=6304;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   if (crypto_generichash_final(hs, nonce, 64)) {
      err=6305;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   memmove(sig+32, sk+32, 32);

   sc_reduce(nonce);
   ge_scalarmult_base(R, nonce);
   ge_p3_tobytes(sig, R);

   if (crypto_generichash_init(hs, NULL, 0, 64)) {
      err=6306;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   if (crypto_generichash_update(hs, sig, 64)) {
      err=6307;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   if (crypto_generichash_update(hs, m, mlen)) {
      err=6308;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   if (crypto_generichash_final(hs, hram, 64)) {
      err=6309;
      goto f_crypto_sign_ed25519_detached_EXIT2;
   }

   sc_reduce(hram);

   sc_muladd(sig + 32, hram, az, nonce);

   sodium_memzero(az, sizeof(az));

   memset(hs, 0, sizeof(crypto_generichash_state));

   memset(R, 0, sizeof(ge_p3));

   memset(hram, 0, sizeof(hram));

   memset(nonce, 0, sizeof(nonce));

   err=0;

f_crypto_sign_ed25519_detached_EXIT2:
   free(hs);

f_crypto_sign_ed25519_detached_EXIT1:
   free(R);

   return err;

}

#ifdef F_ESP32
int IRAM_ATTR crypto_sign_ed25519_seed_keypair2(unsigned char *pk, unsigned char *sk, const unsigned char *seed)
#else
int crypto_sign_ed25519_seed_keypair2(unsigned char *pk, unsigned char *sk, const unsigned char *seed)
#endif
{
    ge_p3 *A;

    A=malloc(sizeof(ge_p3));

    if (!A)
       return 6;

    crypto_generichash(sk, 64, seed, 32, NULL, 0);

    sk[0]&=248;
    sk[31]&=63;
    sk[31]|=64;

    ge_scalarmult_base(A, sk);
    ge_p3_tobytes(pk, A);

    memmove(sk, seed, 32);
    memmove(sk+32, pk, 32);
    memset(A, 0, sizeof(ge_p3));
    free(A);
    return 0;
}

#ifdef F_ESP32
int IRAM_ATTR pk_to_wallet(char *out, char *prefix, NANO_PUBLIC_KEY_EXTENDED pubkey_extended)
#else
int pk_to_wallet(char *out, char *prefix, NANO_PUBLIC_KEY_EXTENDED pubkey_extended)
#endif
{

   uint8_t a, b;
   size_t i, count, pos;
   int err;
   char *fp;
   F_ADD_288 displace;
   extern const char alphabet[] asm("_binary_alphabet_dat_start");

   pos=strlen(prefix);

   if (4>pos)
      return 1;

   crypto_generichash((unsigned char *)(count=(size_t)pubkey_extended+35), 5, pubkey_extended, 32, NULL, 0);

   if ((err=f_reverse((unsigned char *)count, 5)))
      return err;

   memset(displace, 0, sizeof(F_ADD_288));

   if ((err=f_reverse(pubkey_extended, 32)))
      return err;

   memcpy(displace, pubkey_extended, 32);

   f_add_bn_288_le(displace, displace, displace, NULL, 0);
   f_add_bn_288_le(displace, displace, displace, NULL, 0);
   f_add_bn_288_le(displace, displace, displace, NULL, 0);
   f_add_bn_288_le(displace, displace, displace, NULL, 0);
   f_add_bn_288_le(displace, displace, displace, NULL, 0);

   f_reverse(displace, sizeof(displace));

   memcpy(pubkey_extended, ((uint8_t *)displace)+1, sizeof(F_ADD_288)-1);

   count=0;

   fp=out;

   out+=(pos-3);

   for (i=0;i<8;i++) {

      a=pubkey_extended[count++];
      *(out++)=alphabet[(a>>3)];

      b=pubkey_extended[count++];
      *(out++)=alphabet[(((a&0x07)<<2)|(b>>6))];
      *(out++)=alphabet[((b>>1)&0x1F)];

      a=pubkey_extended[count++];
      *(out++)=alphabet[(((b&0x01)<<4)|(a>>4))];

      b=pubkey_extended[count++];
      *(out++)=alphabet[(((a&0x0F)<<1)|(b>>7))];
      *(out++)=alphabet[((b>>2)&0x1F)];

      a=pubkey_extended[count++];
      *(out++)=alphabet[(((b&0x03)<<3)|(a>>5))];
      *(out++)=alphabet[(a&0x1F)];

   }

   out--;

   memcpy(out-8,out-7,8);

   *out=0;

   memcpy(fp, prefix, pos);

   return 0;
}

#ifdef F_ESP32
int IRAM_ATTR f_generate_nano_seed(NANO_SEED seed, uint32_t entropy)
#else
int f_generate_nano_seed(NANO_SEED seed, uint32_t entropy)
#endif
{
   int err;

   err=f_verify_system_entropy_begin();

   if (err)
      return err;

   err=f_verify_system_entropy(entropy, seed, sizeof(NANO_SEED), 1);

   f_verify_system_entropy_finish();

   return err;
}

#ifdef F_ESP32
int IRAM_ATTR f_seed_to_nano_wallet(NANO_PRIVATE_KEY private_key, NANO_PUBLIC_KEY public_key, NANO_SEED seed, uint32_t wallet_number)
#else
int f_seed_to_nano_wallet(NANO_PRIVATE_KEY private_key, NANO_PUBLIC_KEY public_key, NANO_SEED seed, uint32_t wallet_number)
#endif
{
#ifdef F_IA64
   register int err asm("ebx");
#else
   int err;
#endif
   NANO_PRIVATE_KEY_EXTENDED *priv_key_extended;
   crypto_generichash_state *state;
   NANO_SEED *bseed;

   if ((err=sodium_init())<0)
      return err;

   bseed=malloc(sizeof(NANO_SEED));

   if (!bseed)
      return 10;

   state=malloc(sizeof(crypto_generichash_state));

   if (!state) {
      err=8;
      goto f_seed_to_nano_walle_EXIT1;
   }

   priv_key_extended=malloc(sizeof(NANO_PRIVATE_KEY_EXTENDED));

   if (!priv_key_extended) {
      err=5;
      goto f_seed_to_nano_walle_EXIT2;
   }

   if (crypto_generichash_init(state, NULL, 0, 32)) {
      err=30;
      goto f_seed_to_nano_walle_EXIT3;
   }

   if (crypto_generichash_update(state, seed, sizeof(NANO_SEED))) {
      err=31;
      goto f_seed_to_nano_walle_EXIT3;
   }

   asm volatile(
#if F_ARM_A||F_ARM_M||F_THUMB

      "mov %2, %1" "\n\t"
      "strb %2, [%0, #3]" "\n\t"
      "lsr %2, %2, #8" "\n\t"
      "strb %2, [%0, #2]" "\n\t"
      "lsr %2, %2, #8" "\n\t"
      "strb %2, [%0, #1]" "\n\t"
      "lsr %2, %2, #8" "\n\t"
      "strb %2, [%0]" "\n\t"

#else

 #ifdef F_IA64

      "movl %1, %2" "\n\t"
      "xchgb %h2, %b2" "\n\t"
      "movw %w2, 2(%0)" "\n\t"
      "shrl $16, %2" "\n\t"
      "xchgb %h2, %b2" "\n\t"
      "movw %w2, (%0)" "\n\t"

 #else

  #ifdef F_XTENSA

      "extui %2, %1, 24, 8" "\n\t"
      "s8i %2, %0, 0" "\n\t"
      "extui %2, %1, 16, 8" "\n\t"
      "s8i %2, %0, 1" "\n\t"
      "extui %2, %1, 8, 8" "\n\t"
      "s8i %2, %0, 2" "\n\t"
      "extui %2, %1, 0, 8" "\n\t"
      "s8i %2, %0, 3" "\n\t"

  #else

   #error "Assembly error in \"f_seed_to_nano_wallet\" function"

  #endif

 #endif

#endif
      ::"r"(&seed[0]),"r"(wallet_number),"r"(err)
   );


   if (crypto_generichash_update(state, (unsigned char *)seed, sizeof(uint32_t))) {
      err=32;
      goto f_seed_to_nano_walle_EXIT3;
   }

   if (crypto_generichash_final(state, (unsigned char *)bseed, sizeof(NANO_SEED))) {
      err=33;
      goto f_seed_to_nano_walle_EXIT3;
   }

   err=crypto_sign_ed25519_seed_keypair2((unsigned char *)public_key, (unsigned char *)priv_key_extended, (const unsigned char *)bseed);

   memcpy(private_key, priv_key_extended, sizeof(NANO_PRIVATE_KEY));

   memset(priv_key_extended, 0, sizeof(NANO_PUBLIC_KEY_EXTENDED));

   memset(state, 0, sizeof(crypto_generichash_state));

   memset(bseed, 0, sizeof(NANO_SEED));

f_seed_to_nano_walle_EXIT3:
   free(priv_key_extended);

f_seed_to_nano_walle_EXIT2:
   free(state);

f_seed_to_nano_walle_EXIT1:

   free(bseed);

   return err;
}

inline char *f_nano_key_to_str(char *out, unsigned char *key)
{
   return fhex2strv2(out, (const void *)key, sizeof(NANO_SEED), 1);
}

inline int is_null_hash(uint8_t *hash)
{
   return is_filled_with_value(hash, 32, 0);
}

#ifdef F_ESP32
f_nano_err IRAM_ATTR f_nano_balance_to_str(char *str, size_t str_len, size_t *out_len, f_uint128_t value)
#else
f_nano_err f_nano_balance_to_str(char *str, size_t str_len, size_t *out_len, f_uint128_t value)
#endif
{
   int err;
   mbedtls_mpi *X;
   size_t out_len_tmp;

   X=malloc(sizeof(mbedtls_mpi));

   if (!X)
      return NANO_ERR_MALLOC;

   mbedtls_mpi_init(X);

   if (mbedtls_mpi_read_binary(X, value, sizeof(f_uint128_t))) {
      err=NANO_ERR_CANT_PARSE_VALUE;
      goto f_nano_balance_to_str_EXIT2;
   }

   if (mbedtls_mpi_write_string(X, 10, str, str_len, &out_len_tmp)) {
      err=NANO_ERR_PARSE_MPI_TO_STR;
      goto f_nano_balance_to_str_EXIT2;
   }

   err=NANO_ERR_OK;

   if (out_len)
      *out_len=out_len_tmp-1;
/* Changed july 30 2020 21:09
   if (out_len)
      *out_len=out_len_tmp;
   else if (str_len>out_len_tmp)
      str[out_len_tmp]=0;
   else
      err=NANO_ERR_CANT_COMPLETE_NULL_CHAR;
*/
f_nano_balance_to_str_EXIT2:
   mbedtls_mpi_free(X);

//f_nano_balance_to_str_EXIT1:
   free(X);
   return err;
}

//#define NANO_JSON_SZ (size_t)208
#define NANO_JSON_SZ (size_t)224
#define NANO_JSON_MAX_SZ (size_t)4*NANO_JSON_SZ
//int IRAM_ATTR f_nano_transaction_to_JSON(char *str, size_t str_len, size_t *str_out, NANO_PRIVATE_KEY private_key, F_BLOCK_TRANSFER *block_transfer,
//int prefixes) // Primeiro
//int IRAM_ATTR f_nano_transaction_to_JSON(char *str, size_t str_len, size_t *str_out, NANO_PRIVATE_KEY private_key, F_BLOCK_TRANSFER *block_transfer)
#ifdef F_ESP32
int IRAM_ATTR f_nano_transaction_to_JSON(char *str, size_t str_len, size_t *str_out, NANO_PRIVATE_KEY_EXTENDED private_key,
F_BLOCK_TRANSFER *block_transfer)
#else
int f_nano_transaction_to_JSON(char *str, size_t str_len, size_t *str_out, NANO_PRIVATE_KEY_EXTENDED private_key, F_BLOCK_TRANSFER *block_transfer)
#endif
{
   extern char nano_json[] asm("_binary_nano_json_dat_start");
   int err;
   char *data, *fp1, *fp2;
   size_t sz_tmp;

   data=malloc(4*NANO_JSON_MAX_SZ+(MAX_STR_NANO_CHAR+64+3*crypto_sign_BYTES)+1);

   if (!data)
      return 299;

   fp1=data+4*NANO_JSON_MAX_SZ;

   fp2=data+2*NANO_JSON_MAX_SZ;

   memcpy(data, nano_json, NANO_JSON_SZ);

   memset(block_transfer->preamble, 0, 31);

   block_transfer->preamble[31]=0x06;

   if (memcmp(block_transfer->previous, block_transfer->account, 32)==0)
      memset(block_transfer->previous, 0, 32);

   //if (crypto_generichash((unsigned char *)fp1, 32, (const unsigned char *)block_transfer, sizeof(F_BLOCK_TRANSFER)-sizeof(uint64_t), NULL, 0)) {
   if (crypto_generichash((unsigned char *)fp1, 32, (const unsigned char *)block_transfer, F_BLOCK_TRANSFER_SIGNABLE_SZ, NULL, 0)) {
      err=311;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   f_crypto_sign_ed25519_detached((unsigned char *)fp1+32, (const unsigned char *)fp1, 32, (const unsigned char *)private_key);

   //fhex2str((unsigned char *)fp1+32, 64, fp1+32+64); //retirar
   fhex2strv2(fp1+32+64, (const void *)fp1+32, 64, 1);
   memcpy(block_transfer->signature, (const void *)fp1+32, 64);

   if (f_find_replace(fp2, NULL, 2*NANO_JSON_MAX_SZ, data, strlen(data), "%7", fp1+32+64)) {
      err=315;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   memcpy(fp1, block_transfer->account, 32);

   (block_transfer->prefixes&SENDER_XRB)?(memcpy(fp1+PUB_KEY_EXTENDED_MAX_LEN, XRB_PREFIX, sizeof(XRB_PREFIX))):
   (memcpy(fp1+PUB_KEY_EXTENDED_MAX_LEN, NANO_PREFIX, sizeof(NANO_PREFIX)));

   if ((err=pk_to_wallet(fp1+PUB_KEY_EXTENDED_MAX_LEN+sizeof(NANO_PREFIX), fp1+PUB_KEY_EXTENDED_MAX_LEN, (uint8_t *)fp1))) {
      err=317;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   if (f_find_replace(data, NULL, 2*NANO_JSON_MAX_SZ, fp2, strlen(fp2), "%1", fp1+PUB_KEY_EXTENDED_MAX_LEN+sizeof(NANO_PREFIX))) {
      err=301;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   f_nano_key_to_str(fp1, (unsigned char *)block_transfer->previous);

   if (f_find_replace(fp2, NULL, 2*NANO_JSON_MAX_SZ, data, strlen(data), "%2", fp1)) {
      err=303;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   memcpy(fp1, block_transfer->representative, 32);

   (block_transfer->prefixes&REP_XRB)?(memcpy(fp1+PUB_KEY_EXTENDED_MAX_LEN, XRB_PREFIX, sizeof(XRB_PREFIX))):
   (memcpy(fp1+PUB_KEY_EXTENDED_MAX_LEN, NANO_PREFIX, sizeof(NANO_PREFIX)));

   if ((err=pk_to_wallet(fp1+PUB_KEY_EXTENDED_MAX_LEN+sizeof(NANO_PREFIX), fp1+PUB_KEY_EXTENDED_MAX_LEN, (uint8_t *)fp1))) {
      err=319;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   if (f_find_replace(data, NULL, 2*NANO_JSON_MAX_SZ, fp2, strlen(fp2), "%3", fp1+PUB_KEY_EXTENDED_MAX_LEN+sizeof(NANO_PREFIX))) {
      err=304;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   if ((err=f_nano_balance_to_str(fp1, (MAX_STR_NANO_CHAR+64+3*crypto_sign_BYTES)+1, NULL, block_transfer->balance)))
      goto f_nano_transaction_to_JSON_ERR1;

   if (f_find_replace(fp2, NULL, 2*NANO_JSON_MAX_SZ, data, strlen(data), "%5", fp1)) {
      err=305;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   memcpy(fp1, block_transfer->link, 32);

   (block_transfer->prefixes&DEST_XRB)?(memcpy(fp1+PUB_KEY_EXTENDED_MAX_LEN, XRB_PREFIX, sizeof(XRB_PREFIX))):
   (memcpy(fp1+PUB_KEY_EXTENDED_MAX_LEN, NANO_PREFIX, sizeof(NANO_PREFIX)));

   if ((err=pk_to_wallet(fp1+PUB_KEY_EXTENDED_MAX_LEN+sizeof(NANO_PREFIX), fp1+PUB_KEY_EXTENDED_MAX_LEN, (uint8_t *)fp1))) {
      err=321;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   if (f_find_replace(data, NULL, 2*NANO_JSON_MAX_SZ, fp2, strlen(fp2), "%4", fp1+PUB_KEY_EXTENDED_MAX_LEN+sizeof(NANO_PREFIX))) {
      err=306;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   sprintf(fp1, "%016llX", (long long unsigned int)block_transfer->work);

   if (f_find_replace(fp2, NULL, 2*NANO_JSON_MAX_SZ, data, strlen(data), "%6", fp1)) {
      err=308;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   if (f_find_replace(data, &sz_tmp, 2*NANO_JSON_MAX_SZ, fp2, strlen(fp2), "%8", f_nano_key_to_str(fp1, (unsigned char *)block_transfer->link))) {
      err=310;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   if (str_out)
      *str_out=sz_tmp;
   else {
      data[sz_tmp]=0;
      sz_tmp++;
   }

   if (sz_tmp>str_len) {
      err=307;
      goto f_nano_transaction_to_JSON_ERR1;
   }

   memcpy(str, data, sz_tmp);

f_nano_transaction_to_JSON_ERR1:
   memset(data, 0, 4*NANO_JSON_MAX_SZ+(MAX_STR_NANO_CHAR+64+3*crypto_sign_BYTES)+1);
   free(data);

   return err;
}
/////


//int f_nano_block_to_json(char *dest, size_t *olen, size_t dest_size, F_BLOCK_TRANSFER *user_block);
int f_nano_block_to_json(char *dest, size_t *olen, size_t dest_size, F_BLOCK_TRANSFER *user_block)
{

   int err;
   extern char nano_json[] asm("_binary_nano_json_dat_start");
   char *data, *p1, *p2;
   size_t size_tmp;

   if (!is_filled_with_value(user_block->preamble, 31, 0))
      return 12923;

   if (user_block->preamble[31]!=0x06)
      return 12924;

   data=malloc(4*NANO_JSON_MAX_SZ+(MAX_STR_NANO_CHAR+64+3*crypto_sign_BYTES)+1);
   p1=data+2*NANO_JSON_MAX_SZ;
   p2=p1+2*NANO_JSON_MAX_SZ;

   if ((err=pk_to_wallet(p2, (user_block->prefixes&SENDER_XRB)?XRB_PREFIX:NANO_PREFIX, (uint8_t *)memcpy(p2+MAX_STR_NANO_CHAR, user_block->account, 32)))) {

      err=12925;

      goto f_block_to_JSON_EXIT1;

   }

   memcpy(data, nano_json, NANO_JSON_SZ);

   if (f_find_replace(p1, NULL, 2*NANO_JSON_MAX_SZ, data, NANO_JSON_SZ-1, "%1", p2)) {

      err=12926;

      goto f_block_to_JSON_EXIT1;

   }

   if (f_find_replace(data, NULL, 2*NANO_JSON_MAX_SZ, p1, strlen(p1), "%2", f_nano_key_to_str(p2, (unsigned char *)user_block->previous))) {

      err=12927;

      goto f_block_to_JSON_EXIT1;

   }

   if ((err=pk_to_wallet(p2, (user_block->prefixes&REP_XRB)?XRB_PREFIX:NANO_PREFIX, (uint8_t *)memcpy(p2+MAX_STR_NANO_CHAR, user_block->representative, 32)))) {

      err=12928;

      goto f_block_to_JSON_EXIT1;

   }

   if (f_find_replace(p1, NULL, 2*NANO_JSON_MAX_SZ, data, strlen(data), "%3", p2)) {

      err=12929;

      goto f_block_to_JSON_EXIT1;

   }

   if (f_nano_balance_to_str(p2, (MAX_STR_NANO_CHAR+64+3*crypto_sign_BYTES)+1, NULL, user_block->balance)) {

      err=12930;

      goto f_block_to_JSON_EXIT1;

   }

   if (f_find_replace(data, NULL, 2*NANO_JSON_MAX_SZ, p1, strlen(p1), "%5", p2)) {

      err=12929;

      goto f_block_to_JSON_EXIT1;

   }

   if (f_find_replace(p1, NULL, 2*NANO_JSON_MAX_SZ, data, strlen(data), "%8", f_nano_key_to_str(p2, (unsigned char *)user_block->link))) {

      err=12930;

      goto f_block_to_JSON_EXIT1;

   }

   if ((err=pk_to_wallet(p2, (user_block->prefixes&DEST_XRB)?XRB_PREFIX:NANO_PREFIX, (uint8_t *)memcpy(p2+MAX_STR_NANO_CHAR, user_block->link, 32)))) {

      err=12931;

      goto f_block_to_JSON_EXIT1;

   }

   if (f_find_replace(data, NULL, 2*NANO_JSON_MAX_SZ, p1, strlen(p1), "%4", p2)) {

      err=12932;

      goto f_block_to_JSON_EXIT1;

   }

   if (f_find_replace(p1, NULL, 2*NANO_JSON_MAX_SZ, data, strlen(data), "%7", fhex2strv2(p2, user_block->signature, 64, 1))) {

      err=12933;

      goto f_block_to_JSON_EXIT1;

   }

   sprintf(p2, "%016llX", (long long unsigned int)user_block->work);

   if (f_find_replace(data, &size_tmp, 2*NANO_JSON_MAX_SZ, p1, strlen(p1), "%6", p2)) {

      err=12933;

      goto f_block_to_JSON_EXIT1;

   }

   (olen)?(*olen=size_tmp):(data[size_tmp++]=0);

   if (size_tmp>dest_size) {

      err=12934;

      goto f_block_to_JSON_EXIT1;

   }

   err=0;
   memcpy(dest, data, size_tmp);

f_block_to_JSON_EXIT1:
   memset(data, 0, 4*NANO_JSON_MAX_SZ+(MAX_STR_NANO_CHAR+64+3*crypto_sign_BYTES)+1);
   free(data);

   return err;

}


/////
#ifdef F_ESP32
void IRAM_ATTR f_nano_balance_str_adjust(size_t *k, char *value)
#else
void f_nano_balance_str_adjust(size_t *k, char *value)
#endif
{
   char *p1;

   *k=0;

   p1=strchr(value, '.');

   if (p1) {

     *p1=0;

      if ((*k=strlen(++p1))) {

         strcat(value, p1);

         if (*k>30) *k=30;

      }

   }

}

#ifdef F_ESP32
f_nano_err IRAM_ATTR f_nano_parse_raw_str_to_raw128_t(uint8_t *res, const char *raw_str_value)
#else
f_nano_err f_nano_parse_raw_str_to_raw128_t(uint8_t *res, const char *raw_str_value)
#endif
{

   f_nano_err err;
   mbedtls_mpi *A;

   if ((err=valid_raw_balance(raw_str_value)))
      return err;

   if (!(A=malloc(sizeof(mbedtls_mpi))))
      return NANO_ERR_MALLOC;

   mbedtls_mpi_init(A);

   if (mbedtls_mpi_read_string(A, 10, raw_str_value)) {

      err=NANO_ERR_CANT_PARSE_BN_STR;

      goto f_nano_parse_raw_str_to_raw128_t_EXIT1;

   }

   if (mbedtls_mpi_write_binary(A, (unsigned char *)res, sizeof(f_uint128_t)))
      err=NANO_ERR_CANT_PARSE_TO_TEMP_UINT128_T;

f_nano_parse_raw_str_to_raw128_t_EXIT1:
   mbedtls_mpi_free(A);
   memset(A, 0, sizeof(mbedtls_mpi));
   free(A);

   return err;

}

#define NANO_PARSE_REAL_TO_STRING_BUF_SZ (size_t)(F_RAW_STR_MAX_SZ+3*sizeof(mbedtls_mpi))
#ifdef F_ESP32
f_nano_err IRAM_ATTR f_nano_parse_real_str_to_raw128_t(uint8_t *res, const char *real_str_value)
#else
f_nano_err f_nano_parse_real_str_to_raw128_t(uint8_t *res, const char *real_str_value)
#endif
{

   f_nano_err err;
   extern f_uint128_t factor[] asm("_binary_nanobgle_dat_start");
   void *buf;
   char *val_tmp;
   size_t k;
   mbedtls_mpi *X, *A, *B;

   if ((err=f_nano_valid_nano_str_value(real_str_value)))
      return err;

   if (!(buf=malloc(NANO_PARSE_REAL_TO_STRING_BUF_SZ)))
      return NANO_ERR_MALLOC;

   val_tmp=(char *)buf;
   X=(mbedtls_mpi *)(buf+F_RAW_STR_MAX_SZ);
   A=(mbedtls_mpi *)(((uint8_t *)X)+sizeof(mbedtls_mpi));
   B=(mbedtls_mpi *)(((uint8_t *)A)+sizeof(mbedtls_mpi));

   mbedtls_mpi_init(X);
   mbedtls_mpi_init(A);
   mbedtls_mpi_init(B);

   strncpy(val_tmp, real_str_value, F_RAW_STR_MAX_SZ);

   f_nano_balance_str_adjust(&k, val_tmp);

   if (mbedtls_mpi_read_string(A, 10, val_tmp)) {

      err=NANO_ERR_CANT_PARSE_BN_STR;

      goto f_nano_parse_real_str_to_raw128_t_EXIT1;

   }

   if (mbedtls_mpi_read_binary(B, factor[k], sizeof(f_uint128_t))) {

      err=NANO_ERR_CANT_PARSE_FACTOR;

      goto f_nano_parse_real_str_to_raw128_t_EXIT1;

   }

   if (mbedtls_mpi_mul_mpi(X, A, B)) {

      err=NANO_ERR_MPI_MULT;

      goto f_nano_parse_real_str_to_raw128_t_EXIT1;

   }

   err=NANO_ERR_OK;

   if (mbedtls_mpi_write_binary(X, (unsigned char *)res, sizeof(f_uint128_t)))
      err=NANO_ERR_CANT_PARSE_TO_TEMP_UINT128_T;

f_nano_parse_real_str_to_raw128_t_EXIT1:
   mbedtls_mpi_free(B);
   mbedtls_mpi_free(A);
   mbedtls_mpi_free(X);
   memset(buf, 0, NANO_PARSE_REAL_TO_STRING_BUF_SZ);
   free(buf);

   return err;

}

#define NANO_ADD_SUB_BUF_SZ (size_t)(2*sizeof(f_uint128_t)+3*sizeof(mbedtls_mpi))
#ifdef F_ESP32
f_nano_err IRAM_ATTR f_nano_add_sub(void *res, void *valA, void *valB, uint32_t mode)
#else
f_nano_err f_nano_add_sub(void *res, void *valA, void *valB, uint32_t mode)
#endif
{
//X=A+/-C
   f_nano_err err;
   mbedtls_mpi *X, *A, *B;
   uint8_t *raw_balance_tmp;
   void *buf;

   if (!(buf=malloc(NANO_ADD_SUB_BUF_SZ)))
      return NANO_ERR_MALLOC;

   raw_balance_tmp=(uint8_t *)buf;
   A=(mbedtls_mpi *)(buf+2*sizeof(f_uint128_t));

   B=(mbedtls_mpi *)(((uint8_t *)A)+sizeof(mbedtls_mpi));
   X=(mbedtls_mpi *)(((uint8_t *)B)+sizeof(mbedtls_mpi));

   mbedtls_mpi_init(A);
   mbedtls_mpi_init(B);
   mbedtls_mpi_init(X);

   if (mode&(F_NANO_A_REAL_STRING)) {

      if ((err=f_nano_parse_real_str_to_raw128_t(raw_balance_tmp, (const char *)valA)))
         goto f_nano_add_sub_EXIT1;

   } else if (mode&(F_NANO_A_RAW_STRING)) {

      if ((err=f_nano_parse_raw_str_to_raw128_t(raw_balance_tmp, (const char *)valA)))
         goto f_nano_add_sub_EXIT1;

   } else if (mode&(F_NANO_A_RAW_128))
      memcpy(raw_balance_tmp, valA, sizeof(f_uint128_t));
   else {

      err=NANO_ERR_VAL_A_INVALID_MODE;

      goto f_nano_add_sub_EXIT1;

   }

   if (mode&(F_NANO_B_REAL_STRING)) {

      if ((err=f_nano_parse_real_str_to_raw128_t(raw_balance_tmp+sizeof(f_uint128_t), (const char *)valB)))
         goto f_nano_add_sub_EXIT1;

   } else if (mode&(F_NANO_B_RAW_STRING)) {

      if ((err=f_nano_parse_raw_str_to_raw128_t(raw_balance_tmp+sizeof(f_uint128_t), (const char *)valB)))
         goto f_nano_add_sub_EXIT1;

   } else if (mode&(F_NANO_B_RAW_128))
      memcpy(raw_balance_tmp+sizeof(f_uint128_t), valB, sizeof(f_uint128_t));
   else {

      err=NANO_ERR_VAL_B_INVALID_MODE;

      goto f_nano_add_sub_EXIT1;

   }

   if (mbedtls_mpi_read_binary(A, (unsigned char *)raw_balance_tmp, sizeof(f_uint128_t))) {

      err=NANO_ERR_CANT_PARSE_RAW_A_TO_MPI;

      goto f_nano_add_sub_EXIT1;

   }

   if (mbedtls_mpi_read_binary(B, (unsigned char *)(raw_balance_tmp+sizeof(f_uint128_t)), sizeof(f_uint128_t))) {

      err=NANO_ERR_CANT_PARSE_RAW_B_TO_MPI;

      goto f_nano_add_sub_EXIT1;

   }

   if (mode&F_NANO_ADD_A_B) {

      if (mbedtls_mpi_add_mpi(X, A, B)) {

         err=NANO_ERR_ADD_MPI;

         goto f_nano_add_sub_EXIT1;

      }

   } else if (mode&F_NANO_SUB_A_B) {

      if (mbedtls_mpi_cmp_mpi(A, B)==(int)-1) {

         err=NANO_ERR_INSUFICIENT_FUNDS;

         goto f_nano_add_sub_EXIT1;

      }

      if (mbedtls_mpi_sub_mpi(X, A, B)) {

         err=NANO_ERR_SUB_MPI;

         goto f_nano_add_sub_EXIT1;

      }

   } else {

      err=NANO_ERR_UNKNOWN_ADD_SUB_MODE;

      goto f_nano_add_sub_EXIT1;

   }

   if (mbedtls_mpi_write_binary(X, (unsigned char *)raw_balance_tmp, sizeof(f_uint128_t))) {

      err=NANO_ERR_CANT_PARSE_TO_TEMP_UINT128_T;

      goto f_nano_add_sub_EXIT1;

   }

   if (mode&F_NANO_RES_RAW_128) {

      err=NANO_ERR_OK;
      memcpy(res, raw_balance_tmp, sizeof(f_uint128_t));

   } else if (mode&F_NANO_RES_RAW_STRING)
      err=f_nano_balance_to_str((char *)res, 2*F_RAW_STR_MAX_SZ, NULL, raw_balance_tmp); // Bug fixed mbedtls requires 54 bytes to parse to string
      // 2020 jan 26 01:14
   else if (mode&F_NANO_RES_REAL_STRING)
      err=f_nano_raw_to_string((char *)res, NULL, 2*F_RAW_STR_MAX_SZ, raw_balance_tmp, F_RAW_TO_STR_UINT128); 
      // Bug fixed mbedtls requires 54 bytes to parse to string  // 2020 jan 26 01:14
   else
      err=NANO_ERR_INVALID_RES_OUTPUT;

f_nano_add_sub_EXIT1:
   mbedtls_mpi_free(B);
   mbedtls_mpi_free(A);
   mbedtls_mpi_free(X);

   memset(buf, 0, NANO_ADD_SUB_BUF_SZ);
   free(buf);

   return err;

}

#ifdef F_ESP32
f_nano_err IRAM_ATTR f_nano_value_compare_value(void *valA, void *valB, uint32_t *mode_compare)
#else
f_nano_err f_nano_value_compare_value(void *valA, void *valB, uint32_t *mode_compare)
#endif
{

   f_nano_err err;
   void *buf;
   mbedtls_mpi *A, *B;
   uint8_t *value_tmp;
   int compare;

   *mode_compare&=0x0000FFFF;

   if (!(buf=malloc(2*(sizeof(f_uint128_t)+sizeof(mbedtls_mpi)))))
      return NANO_ERR_MALLOC;

   A=(mbedtls_mpi *)buf;
   B=(mbedtls_mpi *)(buf+sizeof(mbedtls_mpi));
   value_tmp=(uint8_t *)(((uint8_t *)B)+sizeof(mbedtls_mpi));

   mbedtls_mpi_init(A);
   mbedtls_mpi_init(B);

   if (*mode_compare&(F_NANO_A_REAL_STRING)) {

      if ((err=f_nano_parse_real_str_to_raw128_t(value_tmp, (const char *)valA)))
         goto f_nano_value_compare_value_EXIT1;

   } else if (*mode_compare&(F_NANO_A_RAW_STRING)) {

      if ((err=f_nano_parse_raw_str_to_raw128_t(value_tmp, (const char *)valA)))
         goto f_nano_value_compare_value_EXIT1;

   } else if (*mode_compare&(F_NANO_A_RAW_128))
      memcpy(value_tmp, valA, sizeof(f_uint128_t));
   else {

      err=NANO_ERR_VAL_A_INVALID_MODE;

      goto f_nano_value_compare_value_EXIT1;

   }

   if (*mode_compare&(F_NANO_B_REAL_STRING)) {

      if ((err=f_nano_parse_real_str_to_raw128_t(value_tmp+sizeof(f_uint128_t), (const char *)valB)))
         goto f_nano_value_compare_value_EXIT1;

   } else if (*mode_compare&(F_NANO_B_RAW_STRING)) {

      if ((err=f_nano_parse_raw_str_to_raw128_t(value_tmp+sizeof(f_uint128_t), (const char *)valB)))
         goto f_nano_value_compare_value_EXIT1;

   } else if (*mode_compare&(F_NANO_B_RAW_128))
      memcpy(value_tmp+sizeof(f_uint128_t), valB, sizeof(f_uint128_t));
   else {

      err=NANO_ERR_VAL_B_INVALID_MODE;

      goto f_nano_value_compare_value_EXIT1;

   }

   if (mbedtls_mpi_read_binary(A, (unsigned char *)value_tmp, sizeof(f_uint128_t))) {

      err=NANO_ERR_CANT_PARSE_RAW_A_TO_MPI;

      goto f_nano_value_compare_value_EXIT1;

   }

   if (mbedtls_mpi_read_binary(B, (unsigned char *)(value_tmp+sizeof(f_uint128_t)), sizeof(f_uint128_t))) {

      err=NANO_ERR_CANT_PARSE_RAW_B_TO_MPI;

      goto f_nano_value_compare_value_EXIT1;

   }

   if ((compare=mbedtls_mpi_cmp_mpi(A, B))>0)
      *mode_compare|=F_NANO_COMPARE_GT;
   else if (compare)
      *mode_compare|=F_NANO_COMPARE_LT;
   else
      *mode_compare|=F_NANO_COMPARE_EQ;

   err=NANO_ERR_OK;

f_nano_value_compare_value_EXIT1:
   mbedtls_mpi_free(B);
   mbedtls_mpi_free(A);

   memset(buf, 0, 2*(sizeof(f_uint128_t)+sizeof(mbedtls_mpi)));
   free(buf);

   return err;

}
//
// Verify funds
// fee can be NULL
// return nonzero if err
#ifdef F_ESP32
f_nano_err IRAM_ATTR f_nano_verify_nano_funds(void *balance, void *value_to_send, void *fee, uint32_t mode)
#else
f_nano_err f_nano_verify_nano_funds(void *balance, void *value_to_send, void *fee, uint32_t mode)
#endif
{

   f_nano_err err;
   uint8_t tmp[sizeof(f_uint128_t)];

   if ((err=f_nano_add_sub(&tmp, balance, value_to_send,
      F_NANO_SUB_A_B|F_NANO_RES_RAW_128|(mode&(~(F_NANO_C_RAW_128|F_NANO_C_RAW_STRING|F_NANO_C_REAL_STRING))))))
      return err;

   if (fee)
      err=f_nano_add_sub(&tmp, &tmp, fee, F_NANO_SUB_A_B|F_NANO_RES_RAW_128|F_NANO_A_RAW_128|(mode>>16));

   return err;

}

#ifdef F_ESP32
int IRAM_ATTR f_nano_seed_to_bip39(char *buf, size_t buf_sz, size_t *out_buf_len, NANO_SEED seed, char *dictionary_file)
#else
int f_nano_seed_to_bip39(char *buf, size_t buf_sz, size_t *out_buf_len, NANO_SEED seed, char *dictionary_file)
#endif
{
   int err, i;
   char *p;
   uint8_t *seed_tmp;
   uint8_t *hash;
   char word[16];
   size_t word_len, out_buf_len_tmp;
   FILE *f;

   seed_tmp=malloc(sizeof(F_ADD_288));

   if (!seed_tmp)
      return 2577;

//   hash=f_sha256_digest((uint8_t *)seed, sizeof(NANO_SEED));
   if ((err = f_sha256_digest((void **)&hash, 0, (uint8_t *)seed, sizeof(NANO_SEED))))
      goto f_nano_seed_to_bip39_EXIT1;

   seed_tmp[32]=hash[0];
   memcpy(seed_tmp, seed, sizeof(NANO_SEED));

   if ((err=f_reverse((unsigned char *)seed_tmp, 33))) {
      err=2579;
      goto f_nano_seed_to_bip39_EXIT1;
   }

   f=fopen(dictionary_file, "r");

   if (!f) {
      err=CANT_OPEN_DICTIONARY_FILE;
      goto f_nano_seed_to_bip39_EXIT1;
   }

   out_buf_len_tmp=0;
   p=buf;

   for (i=0;i<24;i++) {

      f_sl_elv_add_le(seed_tmp, 0);

      *((uint16_t *)(seed_tmp+33))&=0x07FF;

      if (fseek(f, ((size_t)(*((uint16_t *)(seed_tmp+33))))<<4, SEEK_SET)) {
         err=2581;
         goto f_nano_seed_to_bip39_EXIT2;
      }

      if (fread(word, 1, sizeof(word), f)^sizeof(word)) {
         err=2582;
         goto f_nano_seed_to_bip39_EXIT2;
      }

      word_len=strnlen(word, sizeof(word)-1);

      word[word_len++]=' ';

      out_buf_len_tmp+=word_len;

      if (out_buf_len_tmp>buf_sz) {
         err=2583;
         goto f_nano_seed_to_bip39_EXIT2;
      }

      memcpy(p, word, word_len);

      p+=word_len;

   }

   out_buf_len_tmp--;

   (out_buf_len)?(*out_buf_len=out_buf_len_tmp):(buf[out_buf_len_tmp]=0);

   err=0;

f_nano_seed_to_bip39_EXIT2:

   fclose(f);

f_nano_seed_to_bip39_EXIT1:
   memset(seed_tmp, 0, sizeof(F_ADD_288));
   memset(hash, 0, 32);

   free(seed_tmp);

   return err;
}

// july 8 2020 16:08
#define BIP39_MAX_STR_SZ (size_t)384 //24*16
#ifdef F_ESP32
int IRAM_ATTR f_bip39_to_nano_seed(uint8_t *seed, char *str, char *dictionary)
#else
int f_bip39_to_nano_seed(uint8_t *seed, char *str, char *dictionary)
#endif
{
   int err;
   FILE *f;
   char *fp1, *fp2, *bip39_tmp, buf_tmp[16];
   uint8_t *hash;
   static uint8_t seed_tmp[33];
   size_t j, bip39_tmp_sz;

   if ((bip39_tmp_sz=strnlen(str, (BIP39_MAX_STR_SZ+1)))==(BIP39_MAX_STR_SZ+1))
      return 5738;

   if (!bip39_tmp_sz)
      return 5739;

   j=0;

   fp1=str;

   for (;;) {

      if (!(fp1=strchr(fp1, ' ')))
         break;
      fp1++;
      j++;

   }

   if (j!=23)
      return 5735;

   if (!(f=fopen(dictionary, "r")))
      return 5733;

   if (!(fp1=malloc(++bip39_tmp_sz)))
      return 5740;

   fp2=strchr(strcpy(bip39_tmp=fp1, str), ' ');
   *(fp2++)=0;

#ifdef F_ESP32

   esp_task_wdt_init(F_WDT_MAX_ENTROPY_TIME, F_WDT_PANIC);
   esp_task_wdt_add(NULL);
   esp_task_wdt_reset();

#endif

   for (;;) {

      j=0;

      for (;;) {

         if (fread(buf_tmp, 1, sizeof(buf_tmp), f)^sizeof(buf_tmp)) {
            err=5734;
            goto f_bip39_to_nano_seed_EXIT1;
         }

         if (strcmp(fp1, buf_tmp)) {
            j++;
            continue;
         }

         f_sl_elv_add_le(seed_tmp, (int)j);

         break;
      }

      if (!fp2)
         break;

      if (fseek(f, 0L, SEEK_SET))
         return 5736;

      fp1=fp2;

      if ((fp2=strchr(fp2, ' ')))
         *(fp2++)=0;

   }

#ifdef F_ESP32

   if (esp_task_wdt_delete(NULL)!=ESP_OK) {
      err=0x80000001;
      goto f_bip39_to_nano_seed_EXIT1;
   }

   esp_task_wdt_init(F_WDT_MIN_TIME, F_WDT_PANIC);

#endif


   if ((err=f_reverse((unsigned char *)seed_tmp, 33)))
      goto f_bip39_to_nano_seed_EXIT1;

   //hash=f_sha256_digest((uint8_t *)seed_tmp, 32);
   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)seed_tmp, 32)))
      goto f_bip39_to_nano_seed_EXIT1;

   if (hash[0]^seed_tmp[32]) {
      err=5737;
      goto f_bip39_to_nano_seed_EXIT1;
   }

   memcpy(seed, seed_tmp, 32);

f_bip39_to_nano_seed_EXIT1:
   memset(bip39_tmp, 0, bip39_tmp_sz);
   free(bip39_tmp);
   memset(seed_tmp, 0, sizeof(seed_tmp));
   fclose(f);
   return err;
}

/*
#ifdef F_ESP32
int IRAM_ATTR f_bip39_to_nano_seed(uint8_t *seed, char *str, char *dictionary)
#else
int f_bip39_to_nano_seed(uint8_t *seed, char *str, char *dictionary)
#endif
{
   int err;
   FILE *f;
   char *fp1, *fp2;
   uint8_t *hash;
   char buf_tmp[16];
   static uint8_t seed_tmp[33];
   size_t j;

   j=0;

   fp1=str;

   for (;;) {

      fp1=strchr(fp1, ' ');
      if (!fp1) break;
      fp1++;
      j++;

   }

   if (j!=23)
      return 5735;

   f=fopen(dictionary, "r");

   if (!f)
      return 5733;

   fp2=strchr(str, ' ');
   *(fp2++)=0;

   fp1=str;

#ifdef F_ESP32

   esp_task_wdt_init(F_WDT_MAX_ENTROPY_TIME, F_WDT_PANIC);
   esp_task_wdt_add(NULL);
   esp_task_wdt_reset();

#endif

   for (;;) {

      j=0;

      for (;;) {

         if (fread(buf_tmp, 1, sizeof(buf_tmp), f)^sizeof(buf_tmp)) {
            err=5734;
            goto f_bip39_to_nano_seed_EXIT1;
         }

         if (strcmp(fp1, buf_tmp)) {
            j++;
            continue;
         }

         f_sl_elv_add_le(seed_tmp, (int)j);

         break;
      }

      if (!fp2)
         break;

      if (fseek(f, 0L, SEEK_SET))
         return 5736;

      fp1=fp2;

      if ((fp2=strchr(fp2, ' ')))
         *(fp2++)=0;

   }

#ifdef F_ESP32

   if (esp_task_wdt_delete(NULL)!=ESP_OK) {
      err=0x80000001;
      goto f_bip39_to_nano_seed_EXIT1;
   }

   esp_task_wdt_init(F_WDT_MIN_TIME, F_WDT_PANIC);

#endif


   if ((err=f_reverse((unsigned char *)seed_tmp, 33)))
      goto f_bip39_to_nano_seed_EXIT1;

   hash=f_sha256_digest((uint8_t *)seed_tmp, 32);

   if (hash[0]^seed_tmp[32]) {
      err=5737;
      goto f_bip39_to_nano_seed_EXIT1;
   }

   memcpy(seed, seed_tmp, 32);

f_bip39_to_nano_seed_EXIT1:
   memset(seed_tmp, 0, sizeof(seed_tmp));

   fclose(f);

   return err;
}
*/
//
#define READ_NANO_BUFFER_SZ (size_t)(sizeof(F_NANO_CRYPTOWALLET)+32+sizeof(F_ENCRYPTED_BLOCK))
#ifdef F_ESP32
int IRAM_ATTR f_read_seed(uint8_t *seed, const char *passwd, void *source_data, int force_read, int source)
#else
int f_read_seed(uint8_t *seed, const char *passwd, void *source_data, int force_read, int source)
#endif
{
   int err, i;
   FILE *f;
   uint8_t *buffer;
   uint8_t *hash;
   size_t tmp;

   if (!passwd)
      return MISSING_PASSWORD;

   if (!source_data)
      return 7154;

   if ((tmp=strlen(passwd))==0)
      return EMPTY_PASSWORD;

   buffer=malloc(READ_NANO_BUFFER_SZ);

   if (!buffer)
      return 7155;

   err=0;

   if (source&READ_SEED_FROM_STREAM)
      goto f_read_seed_EXIT4;

   if (source&READ_SEED_FROM_FILE) {

      f=fopen((char *)source_data, "r");

      if (!f) {
         err=7160;
         goto f_read_seed_EXIT1;
      }

      if (fread(buffer, 1, sizeof(F_NANO_CRYPTOWALLET), f)^sizeof(F_NANO_CRYPTOWALLET))
         (force_read)?(err=-10):(err=7161);

      fclose(f);

      if (err==0)
         goto f_read_seed_EXIT3;

      if (err>0)
         goto f_read_seed_EXIT2;

      goto f_read_seed_EXIT3_1;

   }

   err=7158;
   goto f_read_seed_EXIT1;

f_read_seed_EXIT4:
   memcpy(buffer, source_data, sizeof(F_NANO_CRYPTOWALLET));

f_read_seed_EXIT3:
   if (memcmp(((F_NANO_CRYPTOWALLET *)buffer)->nano_hdr, NANO_WALLET_MAGIC, sizeof(NANO_WALLET_MAGIC))) {
      err=7162;
      goto f_read_seed_EXIT2;
   }

f_read_seed_EXIT3_1:

//f_pbkdf2_err f_pbkdf2_hmac(unsigned char *f_msg, size_t f_msg_sz, unsigned char *salt, size_t salt_sz, uint8_t *aes_32_dst);
//uint8_t *f_sha256_digest(uint8_t *msg, size_t size);

   //hash=f_sha256_digest((unsigned char *)passwd, tmp);
   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)passwd, tmp)))
      goto f_read_seed_EXIT2;

   for (i=0;i<32;i++)
      ((F_NANO_CRYPTOWALLET *)buffer)->salt[i]^=hash[i];

   if (f_pbkdf2_hmac((unsigned char *)passwd, tmp, (unsigned char *)((F_NANO_CRYPTOWALLET *)buffer)->salt , 32,
                     (unsigned char *)(buffer+sizeof(F_NANO_CRYPTOWALLET)))) {
      err=7163;
      goto f_read_seed_EXIT2;
   }

   if (f_aes256cipher(buffer+sizeof(F_NANO_CRYPTOWALLET), ((F_NANO_CRYPTOWALLET *)buffer)->iv, (void *)&((F_NANO_CRYPTOWALLET *)buffer)->seed_block,
       sizeof(F_ENCRYPTED_BLOCK), (void *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32), MBEDTLS_AES_DECRYPT)) {
       err=7164;
       goto f_read_seed_EXIT2;
   }

   for (i=0;i<32;i++)
      ((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32)))->sub_salt[i]^=hash[i];

   if (f_pbkdf2_hmac((unsigned char *)passwd, tmp, (unsigned char *)((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+
        sizeof(F_NANO_CRYPTOWALLET)+32)))->sub_salt, 32, (unsigned char *)(buffer+sizeof(F_NANO_CRYPTOWALLET)))) {
      err=7165;
      goto f_read_seed_EXIT2;
   }

   if (f_aes256cipher(buffer+sizeof(F_NANO_CRYPTOWALLET), ((F_ENCRYPTED_BLOCK *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32))->iv,
       (void *)((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32)))->sk_encrypted, 32, buffer, MBEDTLS_AES_DECRYPT)) {
       err=7166;
       goto f_read_seed_EXIT2;
   }

   //hash=f_sha256_digest((unsigned char *)buffer, 32);

   if ((err=f_sha256_digest((void **)&hash, 0, buffer, 32)))
      goto f_read_seed_EXIT2;

   if (memcmp(hash, ((F_ENCRYPTED_BLOCK *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32))->hash_sk_unencrypted, 32)) {
      //if (err) {
      if (force_read) {
         err=-11;
         goto f_read_seed_EXIT3_3;
      }

      err=WRONG_PASSWORD;
      goto f_read_seed_EXIT3_2;
   }

f_read_seed_EXIT3_3:
   memcpy(seed, buffer, 32);

f_read_seed_EXIT3_2:
   memset(hash, 0, 32);

f_read_seed_EXIT2:
   memset(buffer, 0, READ_NANO_BUFFER_SZ);

f_read_seed_EXIT1:
   free(buffer);

   return err;
}

#define WRITE_NANO_BUFFER_SZ (size_t)(sizeof(F_NANO_CRYPTOWALLET)+16+32+sizeof(F_ENCRYPTED_BLOCK)+32)
#ifdef F_ESP32
f_write_seed_err IRAM_ATTR f_write_seed(void *source_data, int source, uint8_t *seed, char *passwd)
#else
f_write_seed_err f_write_seed(void *source_data, int source, uint8_t *seed, char *passwd)
#endif
{
   int err;
   size_t tmp, i;
   uint8_t *buffer;
   uint8_t *hash;
   FILE *f;

#ifndef F_ESP32
   if (!f_is_random_attached())
      return ERROR_GEN_TOKEN_NO_RAND_NUM_GEN;
#endif

   if (!passwd)
      return WRITE_ERR_NULL_PASSWORD;

   if (!(buffer=malloc(WRITE_NANO_BUFFER_SZ)))
      return WRITE_ERR_MALLOC;

   if ((tmp=strlen(passwd))==0)
      return WRITE_ERR_EMPTY_STRING;

#ifdef F_ESP32

   esp_fill_random(buffer, WRITE_NANO_BUFFER_SZ);

#else

   f_random(buffer, WRITE_NANO_BUFFER_SZ);

#endif
//f_sha256_digest(void **res, int ret_hex_string, uint8_t *msg, size_t msg_size)
   if ((err=f_sha256_digest((void **)&hash, 0, seed, 32)))
      goto f_write_seed_EXIT1;
/*
   err=WRITE_ERR_OK;

   memcpy(((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+16+32)))->hash_sk_unencrypted,
          f_sha256_digest(seed, 32), 32);
*/

   memcpy(((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+16+32)))->hash_sk_unencrypted, hash, 32);

   //hash=f_sha256_digest((uint8_t *)passwd, tmp);
   if ((err=f_sha256_digest((void **)&hash, 0, passwd, tmp)))
      goto f_write_seed_EXIT1;

   memcpy(((F_NANO_CRYPTOWALLET *)buffer)->nano_hdr, NANO_WALLET_MAGIC, sizeof(NANO_WALLET_MAGIC));

   ((F_NANO_CRYPTOWALLET *)buffer)->ver=F_STREAM_DATA_FILE_VERSION;

   strcpy((char *)((F_NANO_CRYPTOWALLET *)buffer)->description, F_NANO_FILE_DESC);

   memcpy(buffer+sizeof(F_NANO_CRYPTOWALLET), ((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16)))->sub_salt, 48);

   for (i=0;i<32;i++)
      *(buffer+sizeof(F_NANO_CRYPTOWALLET)+i)^=hash[i];

//f_aes_err f_aes256cipher(uint8_t *key, uint8_t iv[16], void *data, size_t data_sz, void *data_out, int direction);
//f_pbkdf2_err f_pbkdf2_hmac(unsigned char *f_msg, size_t f_msg_sz, unsigned char *salt, size_t salt_sz, uint8_t *aes_32_dst);

   if (f_pbkdf2_hmac((unsigned char *)passwd, tmp, buffer+sizeof(F_NANO_CRYPTOWALLET), 32,
       buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16+sizeof(F_ENCRYPTED_BLOCK))) {
       err=WRITE_ERR_GEN_SUB_PRIV_KEY;
       goto f_write_seed_EXIT2;
   }

   if (f_aes256cipher(buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16+sizeof(F_ENCRYPTED_BLOCK), buffer+sizeof(F_NANO_CRYPTOWALLET)+32, 
       (void *)seed, 32, ((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16)))->sk_encrypted, MBEDTLS_AES_ENCRYPT)) {
       err=WRITE_ERR_ENCRYPT_PRIV_KEY;
       goto f_write_seed_EXIT2;
   }

//memcpy(((F_ENCRYPTED_BLOCK *)((uint8_t *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16)))->sk_encrypted, seed, 32);

   memcpy(buffer+sizeof(F_NANO_CRYPTOWALLET), ((F_NANO_CRYPTOWALLET *)buffer)->salt, 48);

   for (i=0;i<32;i++)
      *(buffer+sizeof(F_NANO_CRYPTOWALLET)+i)^=hash[i];

   if (f_pbkdf2_hmac((unsigned char *)passwd, tmp, buffer+sizeof(F_NANO_CRYPTOWALLET), 32,
       buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16+sizeof(F_ENCRYPTED_BLOCK))) {
       err=WRITE_ERR_GEN_MAIN_PRIV_KEY;
       goto f_write_seed_EXIT2;
   }

   if (f_aes256cipher(buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16+sizeof(F_ENCRYPTED_BLOCK), buffer+sizeof(F_NANO_CRYPTOWALLET)+32,
      (void *)(buffer+sizeof(F_NANO_CRYPTOWALLET)+32+16), sizeof(F_ENCRYPTED_BLOCK), (void *)&((F_NANO_CRYPTOWALLET *)buffer)->seed_block,
      MBEDTLS_AES_ENCRYPT)) {
      err=WRITE_ERR_ENCRYPT_SUB_BLOCK;
      goto f_write_seed_EXIT2;
   }

   if (source&WRITE_SEED_TO_STREAM) {
      memcpy(source_data, buffer, sizeof(F_NANO_CRYPTOWALLET));
      goto f_write_seed_EXIT2;
   }

   if (source&WRITE_SEED_TO_FILE) {

      if (f_file_exists((char *)source_data)) {
         err=WRITE_ERR_FILE_ALREDY_EXISTS;
         goto f_write_seed_EXIT2;
      }

      f=fopen((char *)source_data, "w");

      if (!f) {
         err=WRITE_ERR_CREATING_FILE;
         goto f_write_seed_EXIT2;
      }

      if (fwrite(buffer, 1, sizeof(F_NANO_CRYPTOWALLET), f)^sizeof(F_NANO_CRYPTOWALLET))
         err=WRITE_ERR_WRITING_FILE;

      fclose(f);

      goto f_write_seed_EXIT2;
   }

   err=WRITE_ERR_UNKNOWN_OPTION;

f_write_seed_EXIT2:
   memset(hash, 0, 32);
f_write_seed_EXIT1:
   memset(buffer, 0, WRITE_NANO_BUFFER_SZ);
   free(buffer);

   return err;

}

#define NANO_JSON_PARSE_SEED_OFFSET (size_t)224
#define NANO_JSON_PARSE_DATA_SZ (size_t)32
#define NANO_JSON_PARSE_MAX_DATA_SZ (size_t)(NANO_JSON_PARSE_DATA_SZ+16*24+64)
#define BIP39_STR (size_t)16*24
#ifdef F_ESP32
int IRAM_ATTR f_parse_nano_seed_and_bip39_to_JSON(char *dest, size_t dest_sz, size_t *olen, void *source_data, int source, const char *password)
#else
int f_parse_nano_seed_and_bip39_to_JSON(char *dest, size_t dest_sz, size_t *olen, void *source_data, int source, const char *password)
#endif
{
   int err;
   extern char nano_json_data[] asm("_binary_nano_json_dat_start");
   char *buf, *bip39str;
   uint8_t *seed;
   size_t tmp_sz;//, tmp;

   if (!(buf=malloc(2*NANO_JSON_PARSE_MAX_DATA_SZ)))
      return 1674;

   if (!(seed=malloc(32))) {
      err=1675;
      goto f_parse_nano_seed_and_bip39_to_JSON_EXIT1;
   }

   if (source==PARSE_JSON_READ_SEED_GENERIC)
      memcpy(seed, source_data, 32);
   else if ((err=f_read_seed(seed, password, source_data, 0, source)))
      goto f_parse_nano_seed_and_bip39_to_JSON_EXIT2;

   if (f_find_replace(buf+NANO_JSON_PARSE_MAX_DATA_SZ, NULL, NANO_JSON_PARSE_MAX_DATA_SZ, nano_json_data+NANO_JSON_PARSE_SEED_OFFSET,
       strnlen(nano_json_data+NANO_JSON_PARSE_SEED_OFFSET, NANO_JSON_PARSE_DATA_SZ), "%1", f_nano_key_to_str(buf, (unsigned char *)seed))) {
       err=1676;
       goto f_parse_nano_seed_and_bip39_to_JSON_EXIT3;
   }

   if (!(bip39str=malloc(BIP39_STR))) {
      err=1677;
      goto f_parse_nano_seed_and_bip39_to_JSON_EXIT3;
   }

   //if ((err=f_nano_seed_to_bip39(bip39str, BIP39_STR, NULL, seed, BIP39_DICTIONARY)))
   if ((err=f_nano_seed_to_bip39(bip39str, BIP39_STR, NULL, seed, (void *)__dictionary_path)))
      goto f_parse_nano_seed_and_bip39_to_JSON_EXIT4;

   if (f_find_replace(buf, &tmp_sz, NANO_JSON_PARSE_MAX_DATA_SZ, buf+NANO_JSON_PARSE_MAX_DATA_SZ,
       strlen(buf+NANO_JSON_PARSE_MAX_DATA_SZ), "%2", bip39str)) {
       err=1678;
       goto f_parse_nano_seed_and_bip39_to_JSON_EXIT4;
   }

   if (olen)
      *olen=tmp_sz;
   else {
      buf[tmp_sz]=0;
      tmp_sz++;
   }

   if (tmp_sz>dest_sz) {
      err=1679;
      goto f_parse_nano_seed_and_bip39_to_JSON_EXIT4;
   }

   memcpy(dest, buf, tmp_sz);

f_parse_nano_seed_and_bip39_to_JSON_EXIT4:
   memset(bip39str, 0, BIP39_STR);
   free(bip39str);

f_parse_nano_seed_and_bip39_to_JSON_EXIT3:

   memset(seed, 0, 32);
   memset(buf, 0, 2*NANO_JSON_PARSE_MAX_DATA_SZ);

f_parse_nano_seed_and_bip39_to_JSON_EXIT2:
   free(seed);

f_parse_nano_seed_and_bip39_to_JSON_EXIT1:
   free(buf);

   return err;
}

#ifdef F_ESP32
int IRAM_ATTR f_cloud_crypto_wallet_nano_create_seed(size_t entropy, char *file_name, char *password)
#else
int f_cloud_crypto_wallet_nano_create_seed(size_t entropy, char *file_name, char *password)
#endif
{
//NANO_ENCRYPTED_SEED_FILE
   int err;
   NANO_SEED seed;
   char *p;

   (file_name)?(p=file_name):(p=NANO_ENCRYPTED_SEED_FILE);

   if (f_file_exists(p))
      return 8837;

   if ((err=f_generate_nano_seed(seed, entropy)))
      return err;

   err=f_write_seed((void *)p, WRITE_SEED_TO_FILE, (uint8_t *)seed, password);

   memset(seed, 0, sizeof(seed));

   return err;

}
// raw string to real OR raw 128bit to real
//#define F_RAW_STR_MAX_SZ (size_t)41 // 39 + '\0' + '.' -> 39 = log10(2^128)
#define NANO_ADJUST 30 // old or wrong value = 29
#ifdef F_ESP32
int IRAM_ATTR f_nano_raw_to_string(char *str, size_t *olen, size_t str_sz, void *raw, int raw_type)
#else
int f_nano_raw_to_string(char *str, size_t *olen, size_t str_sz, void *raw, int raw_type)
#endif
{
   int err;
   char *buf, *p;
   size_t sz_tmp, tmp;

   if (!(buf=malloc(3*F_RAW_STR_MAX_SZ)))
      return 8860;

   if (raw_type&F_RAW_TO_STR_UINT128) {

      if ((err=f_nano_balance_to_str(buf, 2*F_RAW_STR_MAX_SZ, &sz_tmp, (uint8_t *)raw)))
         goto f_nano_raw_to_string_EXIT1;
        // parse to string in MBEDTLS requires size greater than F_RAW_STR_MAX_SZ (bug fixed) jan 26 2020 01:07
      //sz_tmp--; // bug fixed jan 26  2020 01:07 Adjusting //Ignoring july 2 2020 0:22

      goto f_nano_raw_to_string_EXIT2;

   }

   if (raw_type&F_RAW_TO_STR_STRING) {

      if ((sz_tmp=strnlen((char *)raw, F_RAW_STR_MAX_SZ-1))) {

         if (sz_tmp==(F_RAW_STR_MAX_SZ-1)) {
            err=8861;
            goto f_nano_raw_to_string_EXIT1;
         }

         tmp=sz_tmp;
         p=raw;

         for (;tmp;) {

            tmp--;

            if (isdigit((int)*(p++)))
               continue;

            err=8862;

            goto f_nano_raw_to_string_EXIT1;

         }

         memcpy(buf, raw, sz_tmp);

         goto f_nano_raw_to_string_EXIT2;

      }// else {

      err=8863;
      goto f_nano_raw_to_string_EXIT1;

      //}
   }

   err=8864;

   goto f_nano_raw_to_string_EXIT1;

f_nano_raw_to_string_EXIT2:

   buf[sz_tmp]=0;

   (sz_tmp>NANO_ADJUST)?(void *)(p=buf+(tmp=(sz_tmp-NANO_ADJUST))):(void *)(tmp=0);

   if (tmp) {

      memcpy(buf+2*F_RAW_STR_MAX_SZ, p, NANO_ADJUST);
      buf[2*F_RAW_STR_MAX_SZ+NANO_ADJUST]=0;
      memcpy(p=(buf+F_RAW_STR_MAX_SZ), buf, tmp);
      *(p+=tmp)='.';
      *(++p)=0;

   } else {

      *(p=buf+F_RAW_STR_MAX_SZ)='0';
      *(++p)='.';
      *(++p)=0;

      p=(buf+2*F_RAW_STR_MAX_SZ);

      if ((tmp=(NANO_ADJUST-sz_tmp)))
         memset(p, '0', tmp);

      memcpy((p+=tmp), buf, sz_tmp);
      *(p+sz_tmp)=0;

   }

   tmp=strnlen((p=(buf+2*F_RAW_STR_MAX_SZ)), (F_RAW_STR_MAX_SZ-1));

   p+=tmp;

   for (;tmp;) {

      if (*(--p)=='0') {

         *p=0;
         tmp--;

         continue;

      }

      break;

   }

   p=buf+F_RAW_STR_MAX_SZ;

   for (;;) {

      if (*(p++)=='0') {

         if (*p=='.')
            break;

         continue;

      }

      break;

   }

   p--;

   strncpy(buf, p, F_RAW_STR_MAX_SZ);

   (tmp)?(strncat(buf, buf+2*F_RAW_STR_MAX_SZ, (F_RAW_STR_MAX_SZ-1))):(strncat(buf, "0", (F_RAW_STR_MAX_SZ-1)));

   tmp=strnlen(buf, (F_RAW_STR_MAX_SZ-1));

   (olen)?(*olen=tmp):(tmp++);

   if (tmp>str_sz) {
      err=8865;
      goto f_nano_raw_to_string_EXIT1;
   }

   err=0;

   memcpy(str, buf, tmp);

f_nano_raw_to_string_EXIT1:

   memset(buf, 0, 3*F_RAW_STR_MAX_SZ);
   free(buf);

   return err;

}
// Verifies if "0123456.78900" is valid
// 0 if sucess, othewise error
#ifdef F_ESP32
int IRAM_ATTR f_nano_valid_nano_str_value(const char *str)
#else
int f_nano_valid_nano_str_value(const char *str)
#endif
{//8870
   int err;
   char *buf, *p;
   size_t sz_tmp;

   if ((sz_tmp=strnlen(str, F_RAW_STR_MAX_SZ))==0)
      return 8870;

   if (sz_tmp==F_RAW_STR_MAX_SZ)
      return 8871;

   if (!(buf=malloc(F_RAW_STR_MAX_SZ)))
      return 8872;

   if ((p=strchr((const char *)strncpy(buf, str, F_RAW_STR_MAX_SZ), (int)'.'))) {

      if ((--sz_tmp)==0) {

         err=8873;
         goto f_nano_valid_nano_str_value_EXIT1;

      }

      *p=0;
      strcat(buf, ++p);

   }

   err=0;

   for (;sz_tmp;) {

      if (isdigit((int)buf[--sz_tmp]))
         continue;

      err=8874;

      break;

   }

f_nano_valid_nano_str_value_EXIT1:
   memset(buf, 0, F_RAW_STR_MAX_SZ);
   free(buf);

   return err;

}

// 0 success/ error=non zero
#ifdef F_ESP32
int IRAM_ATTR valid_nano_wallet(const char *wallet)
#else
int valid_nano_wallet(const char *wallet)
#endif
{

   int err;
   uint8_t *res;

   if (!(res=malloc(LIST_STR_WALLET)))
      return 2000;

   err=nano_base_32_2_hex(res, (char *)wallet);

   memset(res, 0, LIST_STR_WALLET);
   free(res);

   return err;

}

#ifdef F_ESP32
int IRAM_ATTR valid_raw_balance(const char *balance)
#else
int valid_raw_balance(const char *balance)
#endif
{

   if (f_is_integer((char *)balance, F_MAX_STR_RAW_BALANCE_MAX))
      return 0;

   return INVALID_RAW_BALANCE;

}
/*
#ifdef F_ESP32
inline int IRAM_ATTR is_nano_prefix(const char *nano_wallet, const char *prefix)
#else
inline int is_nano_prefix(const char *nano_wallet, const char *prefix)
#endif
{

   if (strncmp(nano_wallet, prefix, sizeof(NANO_PREFIX)))
      return 0;

   return 1;

}
*/

#ifdef F_ESP32
inline int IRAM_ATTR is_nano_prefix(const char *nano_wallet, const char *prefix)
#else
inline int is_nano_prefix(const char *nano_wallet, const char *prefix)
#endif
{
   size_t k;

   k=strlen(prefix);

   if (strnlen(nano_wallet, k)^k)
      return 0;
/*
   if ((k=strnlen(nano_wallet, sizeof(NANO_PREFIX)))!=(sizeof(NANO_PREFIX)-1))
      if (k!=(sizeof(XRB_PREFIX)-1))
         return 0;

   //if (strncmp(nano_wallet, prefix, strlen(prefix)))
   if (strncmp(nano_wallet, prefix, sizeof(NANO_PREFIX)))
      return 0;
*/

   if (memcmp(nano_wallet, prefix, k))
      return 0;

   return 1;

}

#ifdef F_ESP32
F_FILE_INFO_ERR IRAM_ATTR f_get_nano_file_info(F_NANO_WALLET_INFO *info)
#else
F_FILE_INFO_ERR f_get_nano_file_info(F_NANO_WALLET_INFO *info)
#endif
{

   F_FILE_INFO_ERR err;
   FILE *f, *g;
   void *buf;
   uint8_t *hash;

   if (!(f=fopen(NANO_FILE_WALLETS_INFO, "r")))
      return F_FILE_INFO_ERR_CANT_OPEN_INFO_FILE;

   if (fread((void *)info, 1, sizeof(F_NANO_WALLET_INFO), f)^sizeof(F_NANO_WALLET_INFO)) {

      err=F_FILE_INFO_ERR_CANT_READ_INFO_FILE;

      goto f_get_nano_file_info_EXIT1;

   }

   if (memcmp(info->header, F_NANO_WALLET_INFO_MAGIC, sizeof(F_NANO_WALLET_INFO_MAGIC))) {

      err=F_FILE_INFO_INVALID_HEADER_FILE;

      goto f_get_nano_file_info_EXIT1;

   }

   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)&info->body, sizeof(F_NANO_WALLET_INFO_BODY))))
      goto f_get_nano_file_info_EXIT1;

   //if (memcmp(info->file_info_integrity, f_sha256_digest((uint8_t *)&info->body, sizeof(F_NANO_WALLET_INFO_BODY)), 32)) {
   if (memcmp(info->file_info_integrity, hash, 32)) {

      err=F_FILE_INFO_ERR_INVALID_SHA256_INFO_FILE;

      goto f_get_nano_file_info_EXIT1;

   }

   if (!(g=fopen(NANO_ENCRYPTED_SEED_FILE, "r"))) {

      fclose(g);
      fclose(f);

      if (unlink(NANO_FILE_WALLETS_INFO))
         return F_FILE_INFO_ERR_CANT_DELETE_NANO_INFO_FILE;

      return F_FILE_INFO_ERR_NANO_SEED_ENCRYPTED_FILE_NOT_FOUND;

   }

   if (info->body.wallet_representative[0])
      if (valid_nano_wallet((const char *)info->body.wallet_representative)) {

         err=F_FILE_INFO_ERR_NANO_INVALID_REPRESENTATIVE;

         goto f_get_nano_file_info_EXIT2;

      }

   if (info->body.max_fee[0])
      if (f_nano_valid_nano_str_value((const char *)info->body.max_fee)) {

         err=F_FILE_INFO_ERR_NANO_INVALID_MAX_FEE_VALUE;

         goto f_get_nano_file_info_EXIT2;

      }

   if (!(buf=malloc(sizeof(F_NANO_CRYPTOWALLET)))) {

      err=F_FILE_INFO_ERR_MALLOC;

      goto f_get_nano_file_info_EXIT2;

   }

   if (fread(buf, 1, sizeof(F_NANO_CRYPTOWALLET), g)^sizeof(F_NANO_CRYPTOWALLET)) {

      err=F_FILE_INFO_ERR_CANT_READ_NANO_SEED_ENCRYPTED_FILE;

      goto f_get_nano_file_info_EXIT3;

   }

   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)buf, sizeof(F_NANO_CRYPTOWALLET))))
      goto f_get_nano_file_info_EXIT3;

   if (memcmp(info->nanoseed_hash, hash, 32)) {
   //if (memcmp(info->nanoseed_hash, f_sha256_digest((uint8_t *)buf, sizeof(F_NANO_CRYPTOWALLET)), 32)) {

      err=F_FILE_INFO_ERR_NANO_SEED_HASH_FAIL;
      fclose(f);
      f=NULL;

      if (unlink(NANO_FILE_WALLETS_INFO))
         err=F_FILE_INFO_ERR_CANT_DELETE_NANO_INFO_FILE;

//      goto f_get_nano_file_info_EXIT3;

   }

//   err=F_FILE_INFO_ERR_OK;


f_get_nano_file_info_EXIT3:
   memset(buf, 0, sizeof(F_NANO_CRYPTOWALLET));
   free(buf);

f_get_nano_file_info_EXIT2:
   fclose(g);

f_get_nano_file_info_EXIT1:
   if (f)
      fclose(f);

   return err;

}

#ifdef F_ESP32
F_FILE_INFO_ERR IRAM_ATTR f_set_nano_file_info(F_NANO_WALLET_INFO *info, int overwrite_existing_file)
#else
F_FILE_INFO_ERR f_set_nano_file_info(F_NANO_WALLET_INFO *info, int overwrite_existing_file)
#endif
{

   F_FILE_INFO_ERR err;
   FILE *f, *g;
   void *buf;
   uint8_t *hash;

   if (overwrite_existing_file)
      if (f_file_exists(NANO_FILE_WALLETS_INFO))
         return F_FILE_INFO_ERR_EXISTING_FILE;

   memcpy(info->header, F_NANO_WALLET_INFO_MAGIC, sizeof(F_NANO_WALLET_INFO_MAGIC));
   info->version=F_NANO_WALLET_INFO_VERSION;

   if (info->desc[0])
      strncpy(info->desc, (const char *)F_NANO_WALLET_INFO_DESC, F_NANO_DESC_SZ);

   if (info->body.wallet_representative[0])
      if (valid_nano_wallet((const char *)info->body.wallet_representative))
         return F_FILE_INFO_ERR_NANO_INVALID_REPRESENTATIVE;

   if (info->body.max_fee[0])
      if (f_nano_valid_nano_str_value((const char *)info->body.max_fee))
         return F_FILE_INFO_ERR_NANO_INVALID_MAX_FEE_VALUE;

   if (!(f=fopen(NANO_ENCRYPTED_SEED_FILE, "r")))
      return F_FILE_INFO_ERR_NANO_SEED_ENCRYPTED_FILE_NOT_FOUND;

   if (!(g=fopen(NANO_FILE_WALLETS_INFO, "w"))) {

      err=F_FILE_INFO_ERR_OPEN_FOR_WRITE_INFO;
      goto f_set_nano_file_info_EXIT1;

   }

   if (!(buf=malloc(sizeof(F_NANO_CRYPTOWALLET)))) {

      err=F_FILE_INFO_ERR_MALLOC;

      goto f_set_nano_file_info_EXIT2;

   }

   if (fread(buf, 1, sizeof(F_NANO_CRYPTOWALLET), f)^sizeof(F_NANO_CRYPTOWALLET)) {

      err=F_FILE_INFO_ERR_CANT_READ_NANO_SEED_ENCRYPTED_FILE;

      goto f_set_nano_file_info_EXIT3;

   }

   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)buf, sizeof(F_NANO_CRYPTOWALLET))))
      goto f_set_nano_file_info_EXIT3;

   memcpy(info->nanoseed_hash, hash, 32);
   //memcpy(info->nanoseed_hash, f_sha256_digest((uint8_t *)buf, sizeof(F_NANO_CRYPTOWALLET)), 32);

   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)&info->body, sizeof(F_NANO_WALLET_INFO))))
      goto f_set_nano_file_info_EXIT3;

   memcpy(info->file_info_integrity, hash, 32);
   //memcpy(info->file_info_integrity, f_sha256_digest((uint8_t *)&info->body, sizeof(F_NANO_WALLET_INFO)), 32);

//   err=F_FILE_INFO_ERR_OK;

   if (fwrite(info, 1, sizeof(F_NANO_WALLET_INFO), g)^sizeof(F_NANO_WALLET_INFO))
      err=F_FILE_INFO_ERR_CANT_WRITE_FILE_INFO;

f_set_nano_file_info_EXIT3:
   memset(buf, 0, sizeof(F_NANO_CRYPTOWALLET));
   free(buf);

f_set_nano_file_info_EXIT2:
   fclose(g);
   if (err)
      if (unlink(NANO_FILE_WALLETS_INFO))
         err=F_FILE_INFO_ERR_CANT_DELETE_NANO_INFO_FILE;

f_set_nano_file_info_EXIT1:
   fclose(f);

   return err;

}
/////////////////////
#define F_P2POW_JSON_SZ (size_t)320//352
//#define F_P2POW_JSON_MAX_SZ 4*F_P2POW_JSON_SZ
#define F_P2POW_JSON_MAX_SZ (size_t)4096
#ifdef F_ESP32
int IRAM_ATTR f_nano_p2pow_to_JSON(char *buffer, size_t *olen, size_t buf_sz, F_BLOCK_TRANSFER *block)
#else
int f_nano_p2pow_to_JSON(char *buffer, size_t *olen, size_t buffer_sz, F_BLOCK_TRANSFER *block)
#endif
{

   int err;
   extern char p2pow_json[] asm("_binary_p2pow_dat_start");
   char *buf, *p;
   char idx[3]={'%', 'a', '\0'};
   size_t sz_tmp;
   F_BLOCK_TRANSFER *blk;

   if (!f_nano_is_valid_block(block))
      return ERROR_NANO_BLOCK;

   if (!f_nano_is_valid_block(&block[1]))
      return ERROR_P2POW_BLOCK;

   if (!(buf=malloc(F_P2POW_JSON_MAX_SZ+MAX_STR_NANO_CHAR+128)))
      return 13013;

   memcpy(buf, p2pow_json, F_P2POW_JSON_SZ);
   blk=block;
   p=buf+(F_P2POW_JSON_MAX_SZ>>1);

f_nano_p2pow_to_JSON_EXIT2:
   if ((err=pk_to_wallet(buf+F_P2POW_JSON_MAX_SZ, (blk->prefixes&SENDER_XRB)?XRB_PREFIX:NANO_PREFIX, 
      (uint8_t *)memcpy(buf+F_P2POW_JSON_MAX_SZ+MAX_STR_NANO_CHAR, blk->account, 32)))) {

      err=13001;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   if (f_find_replace(p, NULL, F_P2POW_JSON_MAX_SZ>>1, buf, strlen(buf), idx, buf+F_P2POW_JSON_MAX_SZ)) {

      err=13002;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   idx[1]++;

   if (f_find_replace(buf, NULL, F_P2POW_JSON_MAX_SZ>>1, p, strlen(p), idx, fhex2strv2(buf+F_P2POW_JSON_MAX_SZ, blk->previous, 32, 1))) {

      err=13003;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   if ((err=pk_to_wallet(buf+F_P2POW_JSON_MAX_SZ, (blk->prefixes&REP_XRB)?XRB_PREFIX:NANO_PREFIX, 
      (uint8_t *)memcpy(buf+F_P2POW_JSON_MAX_SZ+MAX_STR_NANO_CHAR, blk->representative, 32)))) {

      err=13004;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   idx[1]++;

   if (f_find_replace(p, NULL, F_P2POW_JSON_MAX_SZ>>1, buf, strlen(buf), idx, buf+F_P2POW_JSON_MAX_SZ)) {

      err=13005;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   if ((err=f_nano_balance_to_str(buf+F_P2POW_JSON_MAX_SZ, MAX_STR_NANO_CHAR+64, NULL, blk->balance)))
      goto f_nano_p2pow_to_JSON_EXIT1;

   idx[1]++;

   if (f_find_replace(buf, NULL, F_P2POW_JSON_MAX_SZ>>1, p, strlen(p), idx, buf+F_P2POW_JSON_MAX_SZ)) {

      err=13006;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   idx[1]++;

   if (f_find_replace(p, NULL, F_P2POW_JSON_MAX_SZ>>1, buf, strlen(buf), idx, fhex2strv2(buf+F_P2POW_JSON_MAX_SZ, blk->link, 32, 1))) {

      err=13007;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   if ((err=pk_to_wallet(buf+F_P2POW_JSON_MAX_SZ, (blk->prefixes&DEST_XRB)?XRB_PREFIX:NANO_PREFIX, 
      (uint8_t *)memcpy(buf+F_P2POW_JSON_MAX_SZ+MAX_STR_NANO_CHAR, blk->link, 32)))) {

      err=13008;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   idx[1]++;

   if (f_find_replace(buf, NULL, F_P2POW_JSON_MAX_SZ>>1, p, strlen(p), idx, buf+F_P2POW_JSON_MAX_SZ)) {

      err=13009;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   idx[1]++;

   if (idx[1]>'g') {

      if (f_find_replace(p, &sz_tmp, F_P2POW_JSON_MAX_SZ>>1, buf, strlen(buf), idx, fhex2strv2(buf+F_P2POW_JSON_MAX_SZ, blk->signature, 64, 1))) {

         err=13011;

         goto f_nano_p2pow_to_JSON_EXIT1;

      }

   } else {

      if (f_find_replace(p, NULL, F_P2POW_JSON_MAX_SZ>>1, buf, strlen(buf), idx, fhex2strv2(buf+F_P2POW_JSON_MAX_SZ, blk->signature, 64, 1))) {

         err=13010;

         goto f_nano_p2pow_to_JSON_EXIT1;

      }

      strcpy(buf, p);

      idx[1]++;
      blk++;

      goto f_nano_p2pow_to_JSON_EXIT2;

   }

   (olen)?(*olen=sz_tmp):(p[sz_tmp++]=0);

   if (sz_tmp>buffer_sz) {

      err=13012;

      goto f_nano_p2pow_to_JSON_EXIT1;

   }

   memcpy(buffer, p, sz_tmp);

   err=0;

f_nano_p2pow_to_JSON_EXIT1:
   memset(buf, 0, F_P2POW_JSON_MAX_SZ+MAX_STR_NANO_CHAR+128);
   free(buf);

   return err;

}

#ifdef F_ESP32
int IRAM_ATTR f_nano_is_valid_block(F_BLOCK_TRANSFER *block)
#else
int f_nano_is_valid_block(F_BLOCK_TRANSFER *block)
#endif
{

   if (!is_filled_with_value(block->preamble, 31, 0))
      return 0;

   if (block->preamble[31]!=0x06)
      return 0;

   return 1;

}

#ifdef F_ESP32
int IRAM_ATTR f_nano_get_block_hash(uint8_t *hash, F_BLOCK_TRANSFER *block)
#else
int f_nano_get_block_hash(uint8_t *hash, F_BLOCK_TRANSFER *block)
#endif
{

   if (crypto_generichash((unsigned char *)hash, 32, (const unsigned char *)block, F_BLOCK_TRANSFER_SIGNABLE_SZ, NULL, 0))
      return 600;

   return 0;

}

#ifdef F_ESP32
int IRAM_ATTR f_nano_get_p2pow_block_hash(uint8_t *user_hash, uint8_t *fee_hash, F_BLOCK_TRANSFER *block)
#else
int f_nano_get_p2pow_block_hash(uint8_t *user_hash, uint8_t *fee_hash, F_BLOCK_TRANSFER *block)
#endif
{
   int err;
   uint32_t mode;

   if (!f_nano_is_valid_block(block))
      return 601;

   if (!f_nano_is_valid_block(&block[1]))
      return 602;

   if (is_null_hash(block->account))
      return 603;

   if (memcmp(&block[1].account, block->account, 32))
      return 604;

   mode=F_NANO_A_RAW_128|F_NANO_B_RAW_128;

   if ((err=f_nano_value_compare_value((void *)&block[1].balance, (void *)block->balance, &mode)))
      return err;

   if (mode&F_NANO_COMPARE_GEQ)
      return 605;

   if (f_nano_get_block_hash(user_hash, block))
      return 606;

   if (memcmp(user_hash, &block[1].previous, 32))
      return 607;

   if (f_nano_get_block_hash(fee_hash, &block[1]))
      return 608;

/*
   if (!f_nano_is_valid_block(block))
      return 601;

   if (!f_nano_is_valid_block(&block[1]))
      return 602;

   if (memcmp(&block[1].previous, &block[0].previous, 32)==0)
      return 603;

   if (is_null_hash(&block[1].previous))
      return 604;

   if (f_nano_get_block_hash(user_hash, block))
      return 605;

   if (f_nano_get_block_hash(fee_hash, &block[1]))
      return 606;
*/
   return 0;

}

//////////////
#ifdef F_ESP32
int IRAM_ATTR f_nano_sign_block(F_BLOCK_TRANSFER *user_block, F_BLOCK_TRANSFER *fee_block, NANO_PRIVATE_KEY_EXTENDED private_key)
#else
int f_nano_sign_block(F_BLOCK_TRANSFER *user_block, F_BLOCK_TRANSFER *fee_block, NANO_PRIVATE_KEY_EXTENDED private_key)
#endif
{

   int err;
   uint8_t *buf;

   if (!(buf=malloc(32)))
      return 511;

   if (crypto_generichash((unsigned char *)buf, 32, (const unsigned char *)user_block, F_BLOCK_TRANSFER_SIGNABLE_SZ, NULL, 0)) {

      err=512;

      goto f_nano_sign_block_EXIT1;

   }

   f_crypto_sign_ed25519_detached((unsigned char *)user_block->signature, (const unsigned char *)buf, 32, (const unsigned char *)private_key);

   if (fee_block) {

      memcpy(fee_block->previous, buf, 32);

      if (crypto_generichash((unsigned char *)buf, 32, (const unsigned char *)fee_block, F_BLOCK_TRANSFER_SIGNABLE_SZ, NULL, 0)) {

         err=513;

         goto f_nano_sign_block_EXIT1;

      }

      f_crypto_sign_ed25519_detached((unsigned char *)fee_block->signature, (const unsigned char *)buf, 32, (const unsigned char *)private_key);

   }

   err=0;

f_nano_sign_block_EXIT1:
   free(buf);

   return err;

}

#define F_BRAIN_WALLET_LIMIT (int)78
#ifdef F_ESP32
static const uint8_t DRAM_ATTR BRAIN_WALLET_CRACK_LT[][12] = {
#else
static const uint8_t BRAIN_WALLET_CRACK_LT[][12] = {
#endif

   18, 19, 21, 22, 23, 24, 25, 27, 28, 29, 30, (uint8_t)F_BRAIN_WALLET_LIMIT,
   11, 12, 14, 14, 15, 15, 16, 17, 18, 19, 19, 49,
   11, 12, 13, 14, 14, 14, 15, 16, 17, 17, 18, 46,
   13, 14, 15, 16, 17, 17, 18, 19, 20, 21, 21, 55,
   11, 13, 14, 15, 15, 16, 16, 18, 18, 19, 19, 50,
   10, 11, 12, 13, 13, 13, 14, 15, 16, 16, 17, 43,
   10, 11, 12, 12, 13, 13, 14, 15, 15, 16, 16, 42,
   13, 14, 15, 16, 17, 17, 18, 19, 20, 21, 21, 55,
   11, 13, 14, 15, 15, 16, 16, 18, 18, 19, 19, 50,
   10, 11, 12, 13, 13, 13, 14, 15, 16, 16, 17, 43,
   10, 11, 12, 12, 13, 13, 14, 15, 15, 16, 16, 42,
   10, 11, 13, 13, 14, 14, 15, 16, 17, 17, 18, 45,
   10, 11, 12, 13, 13, 14, 14, 15, 16, 16, 17, 43,
    9, 10, 11, 12, 12, 13, 13, 14, 15, 15, 16, 40,
    9, 10, 11, 11, 12, 12, 13, 14, 14, 15, 15, 39

};

#ifdef F_ESP32
static const char DRAM_ATTR CRACK_TIME_TITLE[][64] = {
#else
static const char CRACK_TIME_TITLE[][64] = {
#endif

   "[very poor]. Crack within seconds or less", 
   "[poor]. Crack within minutes",
   "[very bad]. Crack within one hour",
   "[bad]. Crack within one day",
   "[very weak]. Crack within one week",
   "[weak]. Crack within one month",
   "[still weak]. Crack within one year",
   "[maybe good for you]. Crack within one century",
   "[good]. Crack within one thousand year",
   "[very good]. Crack within ten thousand year",
   "[very nice]. Crack withing one hundred thousand year",
   "[Perfect!] 3.34x10^53 Years to crack"

};

#define F_ALL_KIND (int)(F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER|\
F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL|\
F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE|\
F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)

#define F_BRAIN_WALLET_MAX_SZ (size_t)256
#define F_BRAIN_WALLET_MIN_SZ (size_t)9

#ifdef F_ESP32
int IRAM_ATTR f_extract_seed_from_brainwallet(uint8_t *seed, char **warning_msg, uint32_t allow_mode, const char *brainwallet, const char *salt)
#else
int f_extract_seed_from_brainwallet(uint8_t *seed, char **warning_msg, uint32_t allow_mode, const char *brainwallet, const char *salt)
#endif
{
   int err, idx;
   size_t sz_tmp;

   if (warning_msg)
      *warning_msg="Brainwallet Error";

   if (!brainwallet)
      return ERROR_MISSING_BRAINWALLET;

   if (!salt)
      return ERROR_MISSING_SALT;

   if ((err=f_pass_must_have_at_least((char *)brainwallet, F_BRAIN_WALLET_MAX_SZ, F_BRAIN_WALLET_MIN_SZ, F_BRAIN_WALLET_MAX_SZ-1, F_ALL_KIND))&(~F_ALL_KIND))
      return err;

   idx=(err^F_ALL_KIND)-1;

   if ((err=f_pass_must_have_at_least((char *)salt, F_BRAIN_WALLET_MAX_SZ, F_BRAIN_WALLET_MIN_SZ, F_BRAIN_WALLET_MAX_SZ-1, F_PASS_MUST_HAVE_AT_LEAST_NONE)))
      return err+1;

   if ((sz_tmp=strnlen(brainwallet, F_BRAIN_WALLET_MAX_SZ))>F_BRAIN_WALLET_LIMIT) {

      err=F_BRAIN_WALLET_PERFECT;

      goto f_extract_seed_from_brainwallet_EXIT1;

   }

   for (err=0;err<(F_BRAIN_WALLET_PERFECT+1);) {

      if (((size_t)BRAIN_WALLET_CRACK_LT[idx][err])>sz_tmp)
         break;

      err++;

   }

   if (err)
      err--;

f_extract_seed_from_brainwallet_EXIT1:
   if (warning_msg)
      *warning_msg=(char *)&CRACK_TIME_TITLE[err];

   if (allow_mode>err)
      return ERROR_BRAINWALLET_ALLOW_MODE_NOT_ACCEPTED;

   return f_pbkdf2_hmac((unsigned char *)brainwallet, sz_tmp, (unsigned char *)salt, strlen(salt), seed);

}

//>0 if valid, <0 if error or 0 if is invalid
int f_verify_work(uint64_t *result, const unsigned char *hash, uint64_t *work, uint64_t threshold)
{

   int err;
   uint64_t res;
   crypto_generichash_state *state;

   if ((err=sodium_init())<0)
      return err;

   if (!(state=malloc(sizeof(crypto_generichash_state))))
      return -27;

   if (crypto_generichash_init(state, NULL, 0, sizeof(uint64_t)))
      return -28;

   if (crypto_generichash_update(state, (unsigned char *)work, sizeof(uint64_t)))
      return -29;

   if (crypto_generichash_update(state, hash, 32))
      return -30;

   if (crypto_generichash_final(state, (unsigned char *)&res, sizeof(uint64_t)))
      return -31;

   if (result)
      *result=res;

   memset(state, 0, sizeof(crypto_generichash_state));
   free(state);

   return (int)(res>=threshold);

}
/*
 *     - READ_SEED_FROM_STREAM: Read encrypted data from stream pointed in <i>source_data</i>. Password is required.
 *     - READ_SEED_FROM_FILE: Read encrypted data stored in a file where <i>source_data</i> is path to file. Password is required.
*/
#ifdef F_ESP32
int IRAM_ATTR f_is_valid_nano_seed_encrypted(void *stream, size_t stream_len, int from)
#else
int f_is_valid_nano_seed_encrypted(void *stream, size_t stream_len, int read_from)
#endif
{

   int err;
   FILE *f;
   F_NANO_CRYPTOWALLET *encrypted_seed;

   err=0;

   if (read_from&READ_SEED_FROM_STREAM) {

      if (stream_len!=sizeof(F_NANO_CRYPTOWALLET))
         return -191;

      encrypted_seed=(F_NANO_CRYPTOWALLET *)stream;

   } else if (read_from&READ_SEED_FROM_FILE) {

      if (!(f=fopen((const char *)stream, "r")))
         return -192;

      if (!(encrypted_seed=malloc(sizeof(F_NANO_CRYPTOWALLET))))
         return -193;

      if (fread(encrypted_seed, 1, sizeof(F_NANO_CRYPTOWALLET), f)^sizeof(F_NANO_CRYPTOWALLET)) {

         err=-194;
         goto f_is_valid_nano_seed_encrypted_EXIT1;

      }

   } else
      return -195;

   err=(int)(memcmp(encrypted_seed, NANO_WALLET_MAGIC, sizeof(NANO_WALLET_MAGIC))==0);

f_is_valid_nano_seed_encrypted_EXIT1:
   if (read_from&READ_SEED_FROM_FILE) {

      fclose(f);
      memset(encrypted_seed, 0, sizeof(NANO_WALLET_MAGIC));
      free(encrypted_seed);

   }

   return err;

}

#ifdef F_ESP32
int IRAM_ATTR f_sign_data(
   unsigned char *signature, 
   void *out_public_key, 
   uint32_t output_type, 
   const unsigned char *message,
   size_t msg_len, 
   const unsigned char *private_key)
#else
int f_sign_data(
   unsigned char *signature, 
   void *out_public_key, 
   uint32_t output_type, 
   const unsigned char *message,
   size_t msg_len, 
   const unsigned char *private_key)
#endif
{

   int err;
   unsigned char *tmp;

   if (!(tmp=malloc(192)))
      return 12100;

   if ((err=f_crypto_sign_ed25519_detached(tmp, message, msg_len, private_key)))
      goto f_sign_data_EXIT1;

   (output_type&F_SIGNATURE_RAW)?(memcpy(signature, tmp, 64)):(fhex2strv2(signature, tmp, 64, 1));

//   memcpy(tmp, private_key+32, 32);

   if (out_public_key) {

      memcpy(tmp, private_key+32, 32);

      if (output_type&F_SIGNATURE_OUTPUT_RAW_PK)
         memcpy(out_public_key, tmp, 32);
      else if (output_type&F_SIGNATURE_OUTPUT_STRING_PK)
         fhex2strv2(out_public_key, tmp, 32, 1);
      else
         err=pk_to_wallet((char *)out_public_key, (output_type&F_SIGNATURE_OUTPUT_NANO_PK)?(NANO_PREFIX):(XRB_PREFIX), tmp);

   }

   memset(tmp, 0, 192);

f_sign_data_EXIT1:
   free(tmp);

   return err;

}

#ifdef F_ESP32
int IRAM_ATTR f_verify_signed_block(F_BLOCK_TRANSFER *nano_block)
#else
int f_verify_signed_block(F_BLOCK_TRANSFER *nano_block)
#endif
{

   int err;
   uint8_t hash[32];

   if ((err=f_nano_get_block_hash(hash, nano_block)))
      return err;

   return f_crypto_sign_ed25519_verify_detached(
      (const unsigned char *)nano_block->signature,
      (const unsigned char *)hash,
      sizeof(hash),
      (const unsigned char *)nano_block->account);

}

#ifdef F_ESP32
int IRAM_ATTR f_verify_signed_data(
   const unsigned char *signature,
   const unsigned char *message,
   size_t message_len,
   const void *public_key,
   uint32_t pk_type)
#else
int f_verify_signed_data(
   const unsigned char *signature,
   const unsigned char *message,
   size_t message_len,
   const void *public_key,
   uint32_t pk_type)
#endif
{

   int err;
   unsigned char *tmp;
   const unsigned char *p;
   size_t sz_tmp;

   if (!(tmp=malloc(PUB_KEY_EXTENDED_MAX_LEN+MAX_STR_NANO_CHAR+32)))
      return -8937;

   if (pk_type&F_PUBLIC_KEY_RAW_HEX)
      memcpy(tmp, public_key, 32);
   else if (pk_type&F_PUBLIC_KEY_ASCII_HEX) {

      if (strnlen((const char *)public_key, 65)!=64) {

         err=-9938;

         goto f_verify_signed_data_EXIT1;

      }

      if ((err=f_str_to_hex((uint8_t *)tmp, (char *)public_key))) {

         err=-err;

         goto f_verify_signed_data_EXIT1;

      }

   } else if ((err=nano_base_32_2_hex((uint8_t *)tmp, (char *)strncpy((char *)(tmp+PUB_KEY_EXTENDED_MAX_LEN), (const char *)public_key, MAX_STR_NANO_CHAR)))) {

      err=-err;
      goto f_verify_signed_data_EXIT1;

   }

   if (pk_type&F_IS_SIGNATURE_RAW_HEX_STRING) {

      if (strnlen((const char *)signature, 129)!=128) {

         err=-9939;

         goto f_verify_signed_data_EXIT1;

      }

      if ((err=f_str_to_hex((uint8_t *)(tmp+32), (char *)signature))) {

         err=-err;

         goto f_verify_signed_data_EXIT1;

      }

   } else
      memcpy(tmp+32, signature, 64);

   if (pk_type&F_MESSAGE_IS_HASH_STRING) {

      if (strnlen((const char *)message, 65)!=64) {

         err=-9940;

         goto f_verify_signed_data_EXIT1;

      }

      if ((err=f_str_to_hex((uint8_t *)(p=(tmp+32+64)), (char *)message))) {

         err=-err;

         goto f_verify_signed_data_EXIT1;

      }

      sz_tmp=32;

   } else if ((sz_tmp=message_len)) p=message;
   else {
      err=-9941;
      goto f_verify_signed_data_EXIT1;
   }

   err=(f_crypto_sign_ed25519_verify_detached((unsigned char *)(tmp+32), (unsigned char *)p, sz_tmp, tmp)==0);

f_verify_signed_data_EXIT1:
   memset(tmp, 0, PUB_KEY_EXTENDED_MAX_LEN+MAX_STR_NANO_CHAR+32);
   free(tmp);

   return err;

}
/*
if (crypto_sign_verify_detached(sig, MESSAGE, MESSAGE_LEN, pk) != 0) {
    // Incorrect signature!
}
*/
#define MAX_TOKEN_PASSWD_LEN (size_t)256
int f_generate_token(F_TOKEN signature, void *data, size_t data_sz, const char *password)
{

   size_t passwd_len;
   crypto_generichash_state *state;

   if (!f_is_random_attached())
      return ERROR_GEN_TOKEN_NO_RAND_NUM_GEN;//3858;

   if (!data_sz)
      return 3859;

   if (sodium_init()<0)
      return 3860;

   if ((passwd_len=strnlen(password, MAX_TOKEN_PASSWD_LEN))==MAX_TOKEN_PASSWD_LEN)
      return 3861;

   if (passwd_len==0)
      return 3862;

   if (!(state=malloc(sizeof(crypto_generichash_state))))
      return 3863;

   f_random(((uint8_t *)signature)+(sizeof(F_TOKEN)>>2), sizeof(F_TOKEN)>>2);

   *((uint32_t *)signature)=crc32_init((unsigned char *)data, data_sz, *((uint32_t *)(((uint8_t *)signature)+(sizeof(F_TOKEN)>>2))));

   if (crypto_generichash_init(state, NULL, 0, (sizeof(F_TOKEN)>>1)))
      return 3864;

   if (crypto_generichash_update(state, (unsigned char *)data, data_sz))
      return 3865;

   if (crypto_generichash_update(state, (unsigned char *)password, passwd_len))
      return 3866;

   if (crypto_generichash_update(state, (unsigned char *)signature, (sizeof(F_TOKEN)>>1)))
      return 3867;

   if (crypto_generichash_final(state, (unsigned char *)(((uint8_t *)signature)+(sizeof(F_TOKEN)>>1)), (sizeof(F_TOKEN)>>1)))
      return 3868;

   *((uint64_t *)signature)^=*((uint64_t *)((uint8_t *)(signature)+(sizeof(F_TOKEN)>>1)));

   memset(state, 0, sizeof(crypto_generichash_state));
   free(state);

   return 0;

}

int f_verify_token(F_TOKEN signature, void *data, size_t data_sz, const char *password)
{

   size_t passwd_len;
   crypto_generichash_state *state;
   unsigned char tmp[sizeof(F_TOKEN)>>1];

   if (sodium_init()<0)
      return -17860;

   if (!data_sz)
      return -17859;

   if ((passwd_len=strnlen(password, MAX_TOKEN_PASSWD_LEN))==MAX_TOKEN_PASSWD_LEN)
      return -17861;

   if (passwd_len==0)
      return -17862;

   *((uint64_t *)memcpy(tmp, signature, sizeof(F_TOKEN)>>1))^=*((uint64_t *)((uint8_t *)(signature)+(sizeof(F_TOKEN)>>1)));

   if (*((uint32_t *)tmp)^crc32_init((unsigned char *)data, data_sz, *((uint32_t *)(tmp+(sizeof(F_TOKEN)>>2)))))
      return 0;

   if (!(state=malloc(sizeof(crypto_generichash_state))))
      return -17863;

   if (crypto_generichash_init(state, NULL, 0, sizeof(tmp)))
      return -17864;

   if (crypto_generichash_update(state, (unsigned char *)data, data_sz))
      return -17865;

   if (crypto_generichash_update(state, (unsigned char *)password, passwd_len))
      return -17866;

   if (crypto_generichash_update(state, tmp, sizeof(tmp)))
      return -17867;

   if (crypto_generichash_final(state, tmp, sizeof(tmp)))
      return -17868;

   memset(state, 0, sizeof(crypto_generichash_state));
   free(state);

   return (memcmp(tmp, ((uint8_t *)(signature)+(sizeof(F_TOKEN)>>1)), sizeof(tmp))==0);

}

/*
int f_generate_token(F_TOKEN signature, void *data, size_t data_sz, const char *password)
{

   size_t passwd_len;
   crypto_generichash_state *state;

   if (sodium_init()<0)
      return 3860;

   if ((passwd_len=strnlen(password, MAX_TOKEN_PASSWD_LEN))==MAX_TOKEN_PASSWD_LEN)
      return 3861;

   if (passwd_len==0)
      return 3862;

   if (!(state=malloc(sizeof(crypto_generichash_state))))
      return 3863;

   crypto_generichash_init(state, NULL, 0, sizeof(F_TOKEN));
   crypto_generichash_update(state, (unsigned char *)data, data_sz);
   crypto_generichash_update(state, (unsigned char *)password, passwd_len);
   crypto_generichash_final(state, (unsigned char *)signature, sizeof(F_TOKEN));

   memset(state, 0, sizeof(crypto_generichash_state));
   free(state);

   return 0;

}

int f_verify_token(F_TOKEN signature, void *data, size_t data_sz, const char *password)
{

   int err;
   F_TOKEN signature_tmp;

   if ((err=f_generate_token(signature_tmp, data, data_sz, password)))
      return -err;

   return ((memcmp(signature, signature_tmp, sizeof(F_TOKEN)))==0);

}
*/
#ifndef F_ESP32
/*
enum f_nano_account_or_pk_string_to_pk_util_err_t {
   NANO_ACCOUNT_TO_PK_OK = 0,
   NANO_ACCOUNT_TO_PK_OVFL = 8100,
   NANO_ACCOUNT_TO_PK_NULL_STRING,
   NANO_ACCOUNT_WRONG_PK_STR_SZ,
   NANO_ACCOUNT_WRONG_HEX_STRING,
   NANO_ACCOUNT_BASE32_CONVERT_ERROR,
   NANO_ACCOUNT_TO_PK_WRONG_ACCOUNT_LEN
};
*/
int nano_account_or_pk_string_to_pk_util(uint8_t *buffer, int *is_xrb_prefix, const unsigned char *str, size_t str_len)
{
   int err;

   *is_xrb_prefix=0;

   if (str_len==32) {
      memcpy(buffer, str, 32);
      return NANO_ACCOUNT_TO_PK_OK;
   }

   if (str_len)
      return NANO_ACCOUNT_TO_PK_WRONG_ACCOUNT_LEN;

   if ((str_len=strnlen((const char *)str, MAX_STR_NANO_CHAR))==MAX_STR_NANO_CHAR)
      return NANO_ACCOUNT_TO_PK_OVFL;

   if (!str_len)
      return NANO_ACCOUNT_TO_PK_NULL_STRING;

   if (((err=is_nano_prefix(str, NANO_PREFIX)))?(err<<=1):(err=is_nano_prefix(str, XRB_PREFIX))) {
      *is_xrb_prefix=err&1;

      if ((err=nano_base_32_2_hex(buffer, (char *)str)))
         err=NANO_ACCOUNT_BASE32_CONVERT_ERROR;

   } else if (str_len!=64)
      err=NANO_ACCOUNT_WRONG_PK_STR_SZ;
   else if ((err=f_str_to_hex(buffer, (char *)str)))
      err=NANO_ACCOUNT_WRONG_HEX_STRING;

   return err;
}

#define NANO_CREATE_BLK_DYN_BUF_SZ (size_t)128
// in any len is 0 then void * is string with null char at the end
int nano_create_block_dynamic(
   F_BLOCK_TRANSFER **block,
   const void *account,
   size_t account_len,
   const void *previous,
   size_t previous_len,
   const void *representative,
   size_t representative_len,
   const void *balance,
   const void *value_to_send_or_receive,
   uint32_t balance_and_val_to_send_or_rec_types,
   const void *link,
   size_t link_len,
   int direction
)
{
   int err, is_xrb_prefix;
   size_t sz_tmp;
   uint8_t *buffer;
   uint32_t compare;
   F_BLOCK_TRANSFER *blk_tmp;
   uint8_t *p;

   if (!block)
      return NANO_CREATE_BLK_DYN_BLOCK_NULL;

   *block=NULL;

   if (direction&(~(F_VALUE_TO_SEND|F_VALUE_TO_RECEIVE)))
      return NANO_CREATE_BLK_DYN_INVALID_DIRECTION_OPTION;

   if (direction==(F_VALUE_TO_SEND|F_VALUE_TO_RECEIVE))
      return NANO_CREATE_BLK_DYN_INVALID_DIRECTION_OPTION;

   if (balance_and_val_to_send_or_rec_types&(~(F_BALANCE_RAW_128|F_BALANCE_REAL_STRING|F_BALANCE_RAW_STRING|
      F_VALUE_SEND_RECEIVE_RAW_128|F_VALUE_SEND_RECEIVE_REAL_STRING|F_VALUE_SEND_RECEIVE_RAW_STRING)))
      return NANO_CREATE_BLK_DYN_FORBIDDEN_AMOUNT_TYPE;

   if (!account)
      return NANO_CREATE_BLK_DYN_ACCOUNT_NULL;

   if (!previous)
      previous=account;

   if (!representative)
      return NANO_CREATE_BLK_DYN_REP_NULL;

   if (!balance)
      return NANO_CREATE_BLK_DYN_BALANCE_NULL;

   if (!value_to_send_or_receive)
      return NANO_CREATE_BLK_DYN_SEND_RECEIVE_NULL;

   if (!link)
      return NANO_CREATE_BLK_DYN_LINK_NULL;

   if (!(buffer=malloc(NANO_CREATE_BLK_DYN_BUF_SZ)))
      return NANO_CREATE_BLK_DYN_BUF_MALLOC;

   if (!(blk_tmp=malloc(sizeof(F_BLOCK_TRANSFER)))) {
      err=NANO_CREATE_BLK_DYN_MALLOC;
      goto nano_create_block_dynamic_EXIT1;
   }

   memset(blk_tmp, 0, sizeof(F_BLOCK_TRANSFER));

   if ((err=nano_account_or_pk_string_to_pk_util(buffer, &is_xrb_prefix, (const unsigned char *)account, account_len)))
      goto nano_create_block_dynamic_EXIT2;

   blk_tmp->preamble[31]=0x06;
   memcpy(blk_tmp->account, buffer, 32);

   if (is_xrb_prefix)
      blk_tmp->prefixes=SENDER_XRB;

   if (previous==account) {
nano_create_block_dynamic_RET1:
      if (direction&F_VALUE_TO_SEND) {
         err=NANO_CREATE_BLK_DYN_CANT_SEND_IN_GENESIS_BLOCK;
         goto nano_create_block_dynamic_EXIT3;
      }

      compare=(balance_and_val_to_send_or_rec_types&(F_BALANCE_RAW_128|F_BALANCE_REAL_STRING|F_BALANCE_RAW_STRING))|F_NANO_B_RAW_128;

      if (f_nano_value_compare_value((void *)balance, memset(buffer, 0, sizeof(f_uint128_t)), &compare)) {
         err=NANO_CREATE_BLK_DYN_COMPARE_BALANCE;
         goto nano_create_block_dynamic_EXIT3;
      }

      if (!(compare&F_NANO_COMPARE_EQ)) {
         err=NANO_CREATE_BLK_DYN_GENESIS_WITH_NON_EMPTY_BALANCE;
         goto nano_create_block_dynamic_EXIT3;
      }

      p=blk_tmp->account;

   } else if (previous_len==32) {
      p=(uint8_t *)previous;
      goto nano_create_block_dynamic_RET2;
   } else if (previous_len) {
      err=NANO_CREATE_BLK_DYN_WRONG_PREVIOUS_SZ;
      goto nano_create_block_dynamic_EXIT3;
   } else if (strnlen((const char *)previous, 65)==64) {
      if (f_str_to_hex(p=buffer, (char *)previous)) {
         err=NANO_CREATE_BLK_DYN_PARSE_STR_HEX_ERR;
         goto nano_create_block_dynamic_EXIT3;
      }

nano_create_block_dynamic_RET2:
      if (is_null_hash(p))
         goto nano_create_block_dynamic_RET1;

   } else {
      err=NANO_CREATE_BLK_DYN_WRONG_PREVIOUS_STR_SZ;
      goto nano_create_block_dynamic_EXIT3;
   }

   memcpy(blk_tmp->previous, p, 32);

   if ((err=nano_account_or_pk_string_to_pk_util(buffer, &is_xrb_prefix, (const unsigned char *)representative, representative_len)))
      goto nano_create_block_dynamic_EXIT3;

   memcpy(blk_tmp->representative, buffer, 32);

   if (is_xrb_prefix)
      blk_tmp->prefixes|=REP_XRB;

   compare=(balance_and_val_to_send_or_rec_types&(F_VALUE_SEND_RECEIVE_RAW_128|F_VALUE_SEND_RECEIVE_REAL_STRING|F_VALUE_SEND_RECEIVE_RAW_STRING))|F_NANO_A_RAW_128;

   if (f_nano_value_compare_value(memset(buffer, 0, sizeof(f_uint128_t)), (void *)value_to_send_or_receive, &compare)) {
      err=NANO_CREATE_BLK_DYN_COMPARE;
      goto nano_create_block_dynamic_EXIT3;
   }

   if (compare&F_NANO_COMPARE_EQ) {
      err=NANO_CREATE_BLK_DYN_EMPTY_VAL_TO_SEND_OR_REC;
      goto nano_create_block_dynamic_EXIT3;
   }

   if ((err=f_nano_add_sub(blk_tmp->balance, (void *)balance, (void *)value_to_send_or_receive,
      balance_and_val_to_send_or_rec_types|((direction&F_VALUE_TO_RECEIVE)?F_NANO_ADD_A_B:F_NANO_SUB_A_B)|F_NANO_RES_RAW_128)))
      goto nano_create_block_dynamic_EXIT3;

   if ((err=nano_account_or_pk_string_to_pk_util(buffer, &is_xrb_prefix, (const unsigned char *)link, link_len)))
      goto nano_create_block_dynamic_EXIT3;

   memcpy(blk_tmp->link, buffer, 32);

   if (is_xrb_prefix)
      blk_tmp->prefixes|=DEST_XRB;

   goto nano_create_block_dynamic_FINAL;

nano_create_block_dynamic_EXIT3:
   memset(blk_tmp, 0, sizeof(F_BLOCK_TRANSFER));

nano_create_block_dynamic_EXIT2:
   memset(buffer, 0, NANO_CREATE_BLK_DYN_BUF_SZ);
   free(blk_tmp);
   blk_tmp=NULL;

nano_create_block_dynamic_FINAL:
   *block=blk_tmp;

nano_create_block_dynamic_EXIT1:
   free(buffer);

   return err;
}

#define NANO_P2POW_CREATE_BLOCK_BUFFER (size_t)(2*sizeof(F_BLOCK_TRANSFER))
int nano_create_p2pow_block_dynamic(
   F_BLOCK_TRANSFER **p2pow_block,
   F_BLOCK_TRANSFER *block,
   const void *worker_account,
   size_t worker_account_len,
   const void *worker_fee,
   uint32_t worker_fee_type,
   const void *worker_representative,
   size_t worker_representative_len
)
{
   int err;
   uint8_t *prv, rep_xrb_prefix;
   F_BLOCK_TRANSFER *p2pow_tmp;

   if (!p2pow_block)
      return NANO_P2POW_CREATE_OUTPUT;

   *p2pow_block=NULL;

   if (!block)
      return NANO_P2POW_CREATE_BLOCK_NULL;

   if (!f_nano_is_valid_block(block))
      return NANO_P2POW_CREATE_BLOCK_INVALID_USER_BLOCK;

   if (!(prv=malloc(32)))
      return NANO_P2POW_CREATE_BLOCK_MALLOC;

   if ((err=f_nano_get_block_hash(prv, block)))
      goto nano_create_p2pow_block_dynamic_EXIT1;

   rep_xrb_prefix=0;

   if (!worker_representative) {
      worker_representative=(const void *)block->representative;
      worker_representative_len=32;
      rep_xrb_prefix=block->prefixes&REP_XRB;
   }

   if ((err=nano_create_block_dynamic(&p2pow_tmp, (const void *)block->account, 32, (const void *)prv, 32, worker_representative, worker_representative_len,
      block->balance, worker_fee, F_BALANCE_RAW_128|worker_fee_type, worker_account, worker_account_len, F_VALUE_TO_SEND)))
      goto nano_create_p2pow_block_dynamic_EXIT1;

   if (!(*p2pow_block=malloc(2*sizeof(F_BLOCK_TRANSFER)))) {
      err=NANO_P2POW_CREATE_OUTPUT_MALLOC;
      goto nano_create_p2pow_block_dynamic_EXIT2;
   }

   p2pow_tmp->prefixes|=(rep_xrb_prefix|(block->prefixes&SENDER_XRB));
   memcpy(*p2pow_block, block, sizeof(F_BLOCK_TRANSFER));
   memcpy(&(*p2pow_block)[1], p2pow_tmp, sizeof(F_BLOCK_TRANSFER));

nano_create_p2pow_block_dynamic_EXIT2:
   memset(p2pow_tmp, 0, sizeof(F_BLOCK_TRANSFER));
   free(p2pow_tmp);

nano_create_p2pow_block_dynamic_EXIT1:
   memset(prv, 0, 32);
   free(prv);

   return err;
}

/////TODO Implement fast blake2b for POW
/*

static const uint64_t blake2b_IV[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
    0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

enum blake2b_constant {
    BLAKE2B_BLOCKBYTES    = 128,
    BLAKE2B_OUTBYTES      = 64,
    BLAKE2B_KEYBYTES      = 64,
    BLAKE2B_SALTBYTES     = 16,
    BLAKE2B_PERSONALBYTES = 16
};

typedef struct blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t  buf[2 * 128];
    size_t   buflen;
    uint8_t  last_node;
} blake2b_state;

typedef struct blake2b_param_ {
    uint8_t digest_length;
    uint8_t key_length;
    uint8_t fanout;
    uint8_t depth;
    uint8_t leaf_length[4];
    uint8_t node_offset[8];
    uint8_t node_depth;
    uint8_t inner_length;
    uint8_t reserved[14];
    uint8_t salt[BLAKE2B_SALTBYTES];
    uint8_t personal[BLAKE2B_PERSONALBYTES];
} blake2b_param;

static inline int
blake2b_init0(blake2b_state *S)
{
    int i;

    for (i  = 0; i < 8; i++) {
        S->h[i] = blake2b_IV[i];
    }
    // zero everything between .t and .last_node
    memset((void *) &S->t, 0,
           offsetof(blake2b_state, last_node) + sizeof(S->last_node)
           - offsetof(blake2b_state, t));
    return 0;
}

int
blake2b_init_param(blake2b_state *S, const blake2b_param *P)
{
    size_t         i;
    const uint8_t *p;

    blake2b_init0(S);
    p = (const uint8_t *) (P);

    // IV XOR ParamBlock 
    for (i = 0; i < 8; i++) {
        S->h[i] ^= LOAD64_LE(p + sizeof(S->h[i]) * i);
    }
    return 0;
}

int
blake2b_init(blake2b_state *S)
{
    blake2b_param P[1];

    P->digest_length = (const uint8_t)sizeof(uint64_t);
    P->key_length    = 0;
    P->fanout        = 1;
    P->depth         = 1;
    STORE32_LE(P->leaf_length, 0);
    STORE64_LE(P->node_offset, 0);
    P->node_depth   = 0;
    P->inner_length = 0;
    memset(P->reserved, 0, sizeof(P->reserved));
    memset(P->salt, 0, sizeof(P->salt));
    memset(P->personal, 0, sizeof(P->personal));
    return blake2b_init_param(S, P);
}

//// end init

// begin update
int
blake2b_update(blake2b_state *S, const uint8_t *in, uint64_t inlen)
{
   memcpy(S->buf + S->buflen, in, inlen);
   S->buflen += inlen;
   return 0;
}
// end update

int nano_pow_fast_util(uint64_t *nonce, uint64_t *pow, const uint8_t *hash, crypto_generichash_blake2b_state *state) {
//init
//crypto_generichash_init(state, NULL, 0, sizeof(uint64_t));

   if (blake2b_init((blake2b_state *)state) != 0) {

   }
//update
   if (blake2b_update((blake2b_state *)state, (const uint8_t *)pow, sizeof(uint64_t))) {

   }

   if (blake2b_update((blake2b_state *)state, hash, 32)) {

   }



}
*/
void *nano_pow_thread_util(LOCAL_POW_THREAD *local_pow)
{

   int err, flag;
   crypto_generichash_state *state;
   unsigned char *hash;
   uint64_t PoW, nonce_tmp, threshold;

   if (!(state=malloc(sizeof(crypto_generichash_state)))) {

      pthread_mutex_lock(&thr_mtx);
      local_pow->err=F_ERR_THREAD_MALLOC;
      pthread_mutex_unlock(&thr_mtx);

      goto nano_pow_EXIT1;

   }

   if (!(hash=malloc(32))) {

      pthread_mutex_lock(&thr_mtx);
      local_pow->err=F_ERR_THREAD_MALLOC;
      pthread_mutex_unlock(&thr_mtx);

      goto nano_pow_EXIT2;

   }

   if ((err=sodium_init())<0) {

      pthread_mutex_lock(&thr_mtx);
      local_pow->err=F_ERR_THREAD_SODIUM_INIT;
      pthread_mutex_unlock(&thr_mtx);

      goto nano_pow_EXIT2;

   }

   pthread_mutex_lock(&thr_mtx);
   threshold=local_pow->threshold;

   memcpy(hash, local_pow->hash, 32);

   pthread_mutex_unlock(&thr_mtx);

   f_random((void *)&PoW, sizeof(uint64_t));

   while (1) {

      flag=local_pow->flag;
      err=local_pow->err;

      if (flag|err)
         goto nano_pow_EXIT3;

      crypto_generichash_init(state, NULL, 0, sizeof(uint64_t));

      crypto_generichash_update(state, (unsigned char *)&PoW, sizeof(uint64_t));

      crypto_generichash_update(state, hash, 32);

      crypto_generichash_final(state, (unsigned char *)&nonce_tmp, sizeof(uint64_t));

      if (nonce_tmp>=threshold) {

         pthread_mutex_lock(&thr_mtx);

         local_pow->flag=F_FLAG_THREAD_WINNER;
         local_pow->pow=PoW;

         pthread_mutex_unlock(&thr_mtx);

         goto nano_pow_EXIT3;

      }

      PoW++;

   }

nano_pow_EXIT3:
   memset(hash, 0, 32);
   free(hash);

nano_pow_EXIT2:
   memset(state, 0, sizeof(crypto_generichash_state));
   free(state);

nano_pow_EXIT1:
   pthread_exit(NULL);

   return NULL;

}

int f_nano_pow(uint64_t *PoW_res, unsigned char *hash, const uint64_t threshold, int n_thr)
{

   int err, i;
   pthread_t *thr;
   static LOCAL_POW_THREAD local_pow;

   if (!f_is_random_attached())
      return 1114;

   if (n_thr<1)
      return 1111;

   if (n_thr>F_NANO_POW_MAX_THREAD)
      return 1112;

   if (!(thr=malloc(n_thr*sizeof(pthread_t))))
      return 1113;

   memset(&local_pow, 0, sizeof(local_pow));

   local_pow.hash=hash;
   local_pow.threshold=threshold;

   for (i=0;i<n_thr;i++)
      if ((err=pthread_create((thr+i), NULL, (void *)&nano_pow_thread_util, (void *)&local_pow))) {

         local_pow.err=err;

         usleep(100000);

         goto pow_EXIT1;

      }

   while (1) {

      usleep(10000);

      pthread_mutex_lock(&thr_mtx);

      if ((err=local_pow.err)|(local_pow.flag)) {
         usleep(10000);
         break;
      }

      pthread_mutex_unlock(&thr_mtx);

   }

   pthread_mutex_unlock(&thr_mtx); // Bug fixed 07/06/2020

   *PoW_res=local_pow.pow;

pow_EXIT1:
   free(thr);

   return err;

}

#endif

