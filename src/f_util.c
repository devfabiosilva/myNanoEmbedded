/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#ifdef F_XTENSA
 #define F_ESP32
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>

#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/ripemd160.h"

#include "f_util.h"

#ifdef F_ESP32

 #include "esp_system.h"

static uint32_t DRAM_ATTR *__entropy_val=NULL;
static uint8_t DRAM_ATTR *__rand_data=NULL;

#else

#include <termios.h>

static uint32_t *__entropy_val=NULL;
static uint8_t *__rand_data=NULL;
static rnd_fn __rnd_fn=NULL;

#endif

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

int f_verify_system_entropy_begin()
{
   if (!__entropy_val) {
      if (!(__entropy_val=malloc(256*sizeof(uint32_t))))
         return 5001;
   }

   if (!__rand_data) {
     if (!(__rand_data=malloc(F_LOG_MAX))) {
        free(__entropy_val);
        __entropy_val=NULL;
        return 5002;
     }
   }

   return 0;
}

void f_verify_system_entropy_finish()
{
   if (__rand_data) {
      memset(__rand_data, 0, F_LOG_MAX);
      free(__rand_data);
      __rand_data=NULL;
   }

   if (__entropy_val) {
      memset(__entropy_val, 0, 256*sizeof(uint32_t));
      free(__entropy_val);
      __entropy_val=NULL;
   }
}

/*
 * This function synthesizes a good calculation of Entropy of FIOT TRNG Hardware. Also there is a implementation to calculate entropy eficiently using
 * lookup table. All syntheses here is based in equation 7.12 of this amazing MIT opencourseware topic (7.3 A Statistical Definition of Entropy)
 * https://web.mit.edu/16.unified/www/FALL/thermodynamics/notes/node56.html
 * Many thanks to Professor Z. S. Spakovszky
 * Below the implementation of Definition 7.12
 */

int f_verify_system_entropy(uint32_t type, void *rand, size_t rand_sz, int turn_on_wdt)
{
   extern const uint32_t F_LOG_ARRAY[F_LOG_MAX+1] asm("_binary_f_log_dat_start");
   int i;
   uint64_t final;

#ifdef F_ESP32

   if (turn_on_wdt) {
      esp_task_wdt_init(F_WDT_MAX_ENTROPY_TIME, F_WDT_PANIC);
      esp_task_wdt_add(NULL);
      esp_task_wdt_reset();
   }

#endif

f_verify_system_entropy_RET:

   final=0;

#ifdef F_ESP32

   esp_fill_random(__rand_data, F_LOG_MAX);

#else

   f_random(__rand_data, F_LOG_MAX);

#endif

   memset(__entropy_val, 0, 256*sizeof(uint32_t));

   for (i=0;i<F_LOG_MAX;i++)
      __entropy_val[__rand_data[i]]+=1;

   for (i=0;i<256;i++)
      final+=__entropy_val[i]*F_LOG_ARRAY[__entropy_val[i]];

   if ((uint64_t)type>final)
      goto f_verify_system_entropy_RET;

#ifdef F_ESP32

   if (turn_on_wdt) {
      if (esp_task_wdt_delete(NULL)!=ESP_OK)
         return 0x80000001;

      esp_task_wdt_init(F_WDT_MIN_TIME, F_WDT_PANIC);
   }

#endif

   if (rand) {
      if (rand_sz>F_LOG_MAX)
         return 4;
      memcpy(rand, __rand_data, rand_sz); 
   }

   memset(__rand_data, 0, sizeof(F_LOG_MAX));

   return 0;

}

int f_file_exists(char *file)
{
   int err=0;
   FILE *f;

   if ((f=fopen(file, "r"))) {

      err=1;
      fclose(f);

   }

   return err;
}

#ifdef F_ESP32
int IRAM_ATTR f_find_str(size_t *pos, char *str, size_t str_sz, char *what_find)
#else
int f_find_str(size_t *pos, char *str, size_t str_sz, char *what_find)
#endif
{
   int err;
   size_t what_find_sz, i;
   char *p;

   if ((what_find_sz=strlen(what_find))>str_sz)
      return 1;

   p=str;

   err=2;

   for (i=0;i<=(str_sz-what_find_sz);i++) {
      if (memcmp(p++, what_find, what_find_sz))
         continue;
      p--;
      err=0;
      break;
   }

   if (err==0)
      if (pos)
         *pos=(p-str);

   return err;
}

int f_find_replace(char *dest_buf, size_t *out_len, size_t dest_buf_sz, char *str, size_t str_sz, char *what_find, char *what_replace)
{
   int err;
   size_t pos, tmp_dest_buf_sz;
   size_t what_replace_sz, what_find_sz, tmp;
   char *p_str;
   char *p_dest;

   err=f_find_str(&pos, str, str_sz, what_find);

   if (err)
      return err;

   what_replace_sz=strlen(what_replace);

   tmp=what_replace_sz+pos;

   if (tmp>dest_buf_sz)
      return 40;

   p_dest=dest_buf;
   p_str=str;

   if (pos) {
      memcpy(p_dest, p_str, pos);
      p_dest+=pos;
   }

   if (what_replace_sz) {
      memcpy(p_dest, what_replace, what_replace_sz);

      p_dest+=what_replace_sz;

   }

   what_find_sz=strlen(what_find);

   tmp_dest_buf_sz=tmp;

   tmp=pos+what_find_sz;

   p_str+=tmp;

   tmp=(str_sz-tmp);

   if (tmp==0)
      goto f_find_replacef_find_replace_EXIT;

   tmp_dest_buf_sz+=tmp;

   if (tmp_dest_buf_sz>dest_buf_sz)
      return 41;

   memcpy(p_dest, p_str, tmp);

f_find_replacef_find_replace_EXIT:
   if (out_len) {
      *out_len=tmp_dest_buf_sz;
      return 0;
   }

   tmp_dest_buf_sz++;

   if (tmp_dest_buf_sz>dest_buf_sz)
      return 42;

   *(p_dest+=tmp)=0;
   //*(++p_dest)=0;

   return 0;
}

int f_passwd_comp_safe(char *pass1, char *pass2, size_t n, size_t min, size_t max)
{

   size_t k, m;

   if ((k=strnlen(pass1, n))==n)
      return -1000;

   if ((m=strnlen(pass2, n))==n)
      return -1001;

   if (k!=m)
      return -1002;

   if (min>k)
      return -1003;

   if (k>max)
      return -1004;

   if (strcmp(pass1, pass2))
      return -1005;

   return 0;

}

// return 0 if sucess
// !!! Assumes always: n > max >= min
#ifdef F_ESP32
int IRAM_ATTR f_pass_must_have_at_least(char *password, size_t n, size_t min, size_t max, int must_have)
#else
int f_pass_must_have_at_least(char *password, size_t n, size_t min, size_t max, int must_have)
#endif
{
   int err;
   size_t passwd_sz, i;
   char c;

   if ((passwd_sz=strnlen(password, n))==n)
      return F_PASS_IS_OUT_OVF;

   if (min>passwd_sz)
      return F_PASS_IS_TOO_SHORT;

   if (passwd_sz>max)
      return F_PASS_IS_TOO_LONG;

   if ((err=F_PASS_MUST_HAVE_AT_LEAST_NONE)==must_have)
      return err;

   for (i=0;i<passwd_sz;i++) {

      if (err==must_have)
         break;

      c=password[i];

      if (must_have&F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)
         if ((err&F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE)==0) {

            if (c>'z')
               goto f_pass_must_have_at_least_STEP0;

            if (c<'a')
               goto f_pass_must_have_at_least_STEP0;

            err|=F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE;

            continue;

         }

f_pass_must_have_at_least_STEP0:

      if (must_have&F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER)
         if ((err&F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER)==0) {

            if (c>'9')
               goto f_pass_must_have_at_least_STEP1;

            if (c<'0')
               goto f_pass_must_have_at_least_STEP1;

            err|=F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER;

            continue;

         }

f_pass_must_have_at_least_STEP1:

      if (must_have&F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE)
         if ((err&F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE)==0) {

            if (c>'Z')
               goto f_pass_must_have_at_least_STEP2;

            if (c<'A')
               goto f_pass_must_have_at_least_STEP2;

            err|=F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE;

            continue;

         }

f_pass_must_have_at_least_STEP2:

      if (must_have&F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL)
         if ((err&F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL)==0) {

            if (c==0x7F)
               continue;

            if (c<'!')
               continue;

            if (c>'z')
               goto f_pass_must_have_at_least_EXIT1;

            if (c>'`')
               continue;

            if (c>'Z')
               goto f_pass_must_have_at_least_EXIT1;

            if (c>'@')
               continue;

            if (c>'9')
               goto f_pass_must_have_at_least_EXIT1;

            if (c>'/')
               continue;

f_pass_must_have_at_least_EXIT1:
            err|=F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL;

         }

//      if (err==must_have)
//         break;

   }

   return (err^must_have);

}

// returns 1 if success, 0 otherwise
//int f_is_integer(char *value, size_t value_sz)
int f_is_integer_util(char *value, size_t value_sz, int base)
{

   int err;
   size_t sz_tmp;
   char *p;
   typedef int (*h)(int);

   h g;

   if ((sz_tmp=strnlen(p=value, value_sz))==0)
      return 0;

   if (sz_tmp==value_sz)
      return 0;

   err=1;

   switch (base) {

      case 0:
      case 16:

         g=isxdigit;

         if (sz_tmp>2)
            if (strncasecmp("0x", p, 2)==0) {
               p+=2;
               sz_tmp-=2;
            }

         break;

      default:
         g=isdigit;

   }

   for (;sz_tmp;) {

      if (g((int)p[--sz_tmp]))
         continue;

      err=0;

      break;

   }

   return err;

}

inline int f_is_integer(char *value, size_t value_sz) { return f_is_integer_util(value, value_sz, 10); }

// return 1 if is filled with value or 0 if not
int is_filled_with_value(uint8_t *value, size_t value_sz, uint8_t ch)
{

   int res=1;

   for (;value_sz;) {

      if (value[--value_sz]==ch)
         continue;

      res=0;

      break;

   }

   return res;

}

char *fhex2strv2(char *res, const void *buf, size_t buf_sz, int is_uppercase)
{

   char *p=res;
   const char *f[]={"%02x","%02X"};
   const char *q=f[is_uppercase&1];

   for (;buf_sz--;) {

      sprintf(p, q, (unsigned char)*((unsigned char *)buf++));
      p+=2;

   }

   return res;

}

#ifdef F_ESP32
int IRAM_ATTR f_sha256_digest(void **res, int ret_hex_string, uint8_t *msg, size_t msg_size)
#else
int f_sha256_digest(void **res, int ret_hex_string, uint8_t *msg, size_t msg_size)
#endif
{
   int err;
   mbedtls_sha256_context *sha256;
   static uint8_t result256sum[32+65];

   *res = NULL;

   if (!(sha256 = malloc(sizeof(mbedtls_sha256_context))))
      return 5862;

   mbedtls_sha256_init(sha256);

   if ((err = mbedtls_sha256_starts_ret(sha256, 0)))
      goto f_sha256_digest_EXIT;

   if ((err = mbedtls_sha256_update_ret(sha256, msg, msg_size)))
      goto f_sha256_digest_EXIT;

   if ((err = mbedtls_sha256_finish_ret(sha256, result256sum)))
      goto f_sha256_digest_EXIT;

   *res = (void *)(ret_hex_string)?(void *)fhex2strv2((char *)(result256sum + 32), result256sum, 32, 0):(void *)result256sum;

f_sha256_digest_EXIT:
   mbedtls_sha256_free(sha256);
   memset(sha256, 0, sizeof(mbedtls_sha256_context));
   free(sha256);

   return err;
}

f_pbkdf2_err f_pbkdf2_hmac(unsigned char *f_msg, size_t f_msg_sz, unsigned char *salt, size_t salt_sz, uint8_t *aes_32_dst)
{
    int err;
    mbedtls_md_context_t sha_ctx;

    const mbedtls_md_info_t *info_sha;

    mbedtls_md_init(&sha_ctx);

    info_sha=mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (info_sha==NULL) {
        mbedtls_md_free(&sha_ctx);
        return F_PBKDF2_ERR_INFO_SHA;
    }
    err=mbedtls_md_setup(&sha_ctx, info_sha, 1);

    if (err)
        return F_PBKDF2_ERR_CTX;

    err=mbedtls_pkcs5_pbkdf2_hmac(&sha_ctx, f_msg, f_msg_sz, salt, salt_sz, F_PBKDF2_ITER_SZ, 32, aes_32_dst);

    mbedtls_md_free(&sha_ctx);

    if (err)
       return F_PBKDF2_ERR_PKCS5;

    return F_PBKDF2_RESULT_OK;
}

f_md_hmac_sha512 f_hmac_sha512(unsigned char *result, const unsigned char *key, size_t key_len, const unsigned char *data, size_t data_len)
{
   int err;
   mbedtls_md_context_t *sha512_ctx;
   const mbedtls_md_info_t *info_sha;

   if (!(sha512_ctx=malloc(sizeof(mbedtls_md_context_t))))
      return F_HMAC_SHA512_MALLOC;

   if (!(info_sha=mbedtls_md_info_from_type(MBEDTLS_MD_SHA512))) {
      err=F_HMAC_SHA512_ERR_INFO;
      goto f_hmac_sha512_EXIT1;
   }

   mbedtls_md_init(sha512_ctx);

   if (mbedtls_md_setup(sha512_ctx, info_sha, 1)) {
      err=F_HMAC_SHA512_ERR_SETUP;
      goto f_hmac_sha512_EXIT2;
   }

   err=F_HMAC_SHA512_OK;

   if (mbedtls_md_hmac(info_sha, key, key_len, data, data_len, result))
      err=F_HMAC_SHA512_DIGEST_ERROR;

f_hmac_sha512_EXIT2:
   mbedtls_md_free(sha512_ctx);

f_hmac_sha512_EXIT1:
   memset(sha512_ctx, 0, sizeof(mbedtls_md_context_t));
   free(sha512_ctx);
   return err;
}

#define GET_EC_SZ_UTIL_NOT_IMPLEMENTED_YET (int)35000
int get_ec_sz_util(size_t *sz, mbedtls_ecp_group_id gid)
{

   switch (gid) {
      case MBEDTLS_ECP_DP_SECP256K1:
      case MBEDTLS_ECP_DP_BP256R1:
      case MBEDTLS_ECP_DP_SECP256R1:
         *sz=32;
         return 0;

      case MBEDTLS_ECP_DP_SECP384R1:
      case MBEDTLS_ECP_DP_BP384R1:
         *sz=48;
         return 0;

      case MBEDTLS_ECP_DP_SECP224R1:
      case MBEDTLS_ECP_DP_SECP224K1:
         *sz=28;
         return 0;

      case MBEDTLS_ECP_DP_SECP192R1:
      case MBEDTLS_ECP_DP_SECP192K1:
         *sz=24;
         return 0;

      case MBEDTLS_ECP_DP_CURVE448:
         *sz=56;
         return 0;

      case MBEDTLS_ECP_DP_BP512R1:
         *sz=64;
         return 0;

   }

   return GET_EC_SZ_UTIL_NOT_IMPLEMENTED_YET;
}

f_ecdsa_key_pair_err f_gen_ecdsa_key_pair(f_ecdsa_key_pair *f_key_pair, int format, fn_det fn, void *fn_det_ctx)
{
   int err;
   mbedtls_ecdsa_context *f_ctx_tmp;

   if (!f_key_pair)
      return F_ECDSA_KEY_PAIR_NULL;

   if (f_key_pair->ctx)
      f_ctx_tmp=f_key_pair->ctx;
   else if ((f_ctx_tmp=malloc(sizeof(mbedtls_ecdsa_context))))
      mbedtls_ecdsa_init(f_ctx_tmp);
   else
      return F_ECDSA_KEY_PAIR_MALLOC;

   if ((err=mbedtls_ecdsa_genkey(f_ctx_tmp, f_key_pair->gid, fn, fn_det_ctx)))
      goto f_gen_ecdsa_key_pair_EXIT1;

/* WARNING !!!
The value returned by this function may be less than the number of bytes used to store X internally. This happens if and only if there are trailing bytes of value zero.
https://tls.mbed.org/api/bignum_8h.html#a681ab2710d044c0cb091b6497c6ed395

   f_key_pair->private_key_sz=mbedtls_mpi_size(&f_ctx_tmp->d);
   using int get_ec_sz_util(size_t *sz, int format) instead
*/
   if ((err=get_ec_sz_util(&f_key_pair->private_key_sz, f_key_pair->gid)))
      goto f_gen_ecdsa_key_pair_EXIT1;

   if ((err=mbedtls_mpi_write_binary(&f_ctx_tmp->d, f_key_pair->private_key, f_key_pair->private_key_sz)))
      goto f_gen_ecdsa_key_pair_EXIT1;

   err=mbedtls_ecp_point_write_binary(
      &f_ctx_tmp->grp, &f_ctx_tmp->Q, format, &f_key_pair->public_key_sz, f_key_pair->public_key, sizeof(f_key_pair->public_key));

f_gen_ecdsa_key_pair_EXIT1:
   if (!f_key_pair->ctx) {
      mbedtls_ecdsa_free(f_ctx_tmp);
      memset(f_ctx_tmp, 0, sizeof(mbedtls_ecdsa_context));
      free(f_ctx_tmp);
   }

   return err;
}

f_aes_err f_aes256cipher(uint8_t *key, uint8_t *iv, void *data, size_t data_sz, void *data_out, int direction)
{
   int err;
   mbedtls_aes_context *ctx;

   ctx=malloc(sizeof(mbedtls_aes_context));

   if (!ctx)
      return F_AES_ERR_MALLOC;

   mbedtls_aes_init(ctx);

   err=F_AES_RESULT_OK;

   if (direction==MBEDTLS_AES_ENCRYPT) {

      if (mbedtls_aes_setkey_enc(ctx, key, 256)) {
         err=F_AES_ERR_ENCKEY;
         goto f_aes256cipher_EXIT1;
      }

      goto f_aes256cipher_EXIT2;

   }

   if (direction==MBEDTLS_AES_DECRYPT) {

      if (mbedtls_aes_setkey_dec(ctx, key, 256)) {
         err=F_AES_ERR_DECKEY;
         goto f_aes256cipher_EXIT1;
      }

      goto f_aes256cipher_EXIT2;

   }

   err=F_AES_UNKNOW_DIRECTION;

   goto f_aes256cipher_EXIT1;

f_aes256cipher_EXIT2:
   if (mbedtls_aes_crypt_cbc(ctx, direction, data_sz, iv, (const unsigned char *)data, (unsigned char *)data_out))
      err=F_ERR_ENC_DECRYPT_FAILED;

f_aes256cipher_EXIT1:
   mbedtls_aes_free(ctx);

   memset(ctx, 0, sizeof(mbedtls_aes_context));

   free(ctx);

   return err;
}
// Checks if secret key generated in HMAC is valid = 0, error = non zero
#define F_ECDSA_BUFFER_SZ (size_t)(sizeof(mbedtls_ecdsa_context)+sizeof(mbedtls_mpi))
int f_ecdsa_secret_key_valid(mbedtls_ecp_group_id gid, unsigned char *secret_key, size_t secret_key_len)
{
   int err;
   uint8_t *buffer;
   mbedtls_ecdsa_context *ecdsa_ctx;
   mbedtls_mpi *A;

   if (!secret_key_len)
      return 476;

   if (!(buffer=malloc(F_ECDSA_BUFFER_SZ)))
      return 477;

   ecdsa_ctx=(mbedtls_ecdsa_context *)buffer;
   A=(mbedtls_mpi *)(buffer+sizeof(mbedtls_ecdsa_context));

   mbedtls_ecdsa_init(ecdsa_ctx);

   if (err=(mbedtls_ecp_group_load(&ecdsa_ctx->grp, gid)))
      goto f_ecdsa_secret_key_valid_EXIT1;

   mbedtls_mpi_init(A);

   if (mbedtls_mpi_read_binary(A, secret_key, secret_key_len)) {
      err=480;
      goto f_ecdsa_secret_key_valid_EXIT2;
   }

   err=0;

   if (mbedtls_ecp_check_privkey(&ecdsa_ctx->grp, A))
      err=481;

f_ecdsa_secret_key_valid_EXIT2:
   mbedtls_mpi_free(A);

f_ecdsa_secret_key_valid_EXIT1:
   mbedtls_ecdsa_free(ecdsa_ctx);
   memset(buffer, 0, F_ECDSA_BUFFER_SZ);
   free(buffer);
   return err;
}

#define F_ECDSA_PUBLIC_BUFFER_SZ (size_t)(sizeof(mbedtls_ecdsa_context)+sizeof(mbedtls_ecp_point))
int f_ecdsa_public_key_valid(mbedtls_ecp_group_id gid, unsigned char *public_key, size_t public_key_len)
{
   int err;
   uint8_t *buffer;
   mbedtls_ecdsa_context *ecdsa_ctx;
   mbedtls_ecp_point *P;

   if (!public_key_len)
      return 500;

   if (!(buffer=malloc(F_ECDSA_PUBLIC_BUFFER_SZ)))
      return 501;

   ecdsa_ctx=(mbedtls_ecdsa_context *)buffer;
   P=(mbedtls_ecp_point *)(buffer+sizeof(mbedtls_ecdsa_context));

   mbedtls_ecdsa_init(ecdsa_ctx);
   mbedtls_ecp_point_init(P);

   if ((err=(mbedtls_ecp_group_load(&ecdsa_ctx->grp, gid))))
      goto f_ecdsa_public_key_valid_EXIT1;
// issue: https://github.com/ARMmbed/mbedtls/pull/1608
   if ((err=mbedtls_ecp_point_read_binary(&ecdsa_ctx->grp, P, public_key, public_key_len)))
      goto f_ecdsa_public_key_valid_EXIT1;

   err=0;
   if (mbedtls_ecp_check_pubkey(&ecdsa_ctx->grp, P))
      err=503;

f_ecdsa_public_key_valid_EXIT1:
   mbedtls_ecp_point_free(P);
   mbedtls_ecdsa_free(ecdsa_ctx);
   memset(buffer, 0, F_ECDSA_PUBLIC_BUFFER_SZ);
   free(buffer);
   return err;
}

#define UNCOMPRESS_BUFFER_SZ (size_t)(4*sizeof(mbedtls_mpi)+sizeof(mbedtls_ecdsa_context))
int f_uncompress_elliptic_curve(uint8_t *output, size_t output_sz, size_t *olen, mbedtls_ecp_group_id gid, uint8_t *public_key, size_t public_key_sz)
{
   int err;
   size_t sz_tmp, sz_tmp2;
   mbedtls_mpi *_RR, *X, *R, *N;
   mbedtls_ecdsa_context *ecdsa_ctx;
   uint8_t *buffer;

   if ((public_key[0]!=0x02)&&(public_key[0]!=0x03))
      return 603;

   if (!(buffer=malloc(UNCOMPRESS_BUFFER_SZ)))
      return 600;

   mbedtls_ecdsa_init(ecdsa_ctx=(mbedtls_ecdsa_context *)buffer);

   if ((err=(mbedtls_ecp_group_load(&ecdsa_ctx->grp, gid))))
      goto f_uncompress_elliptic_curve_EXIT1;

   if ((sz_tmp=mbedtls_mpi_size(&ecdsa_ctx->grp.P))!=(sz_tmp2=(public_key_sz-1))) {
      err=601;
      goto f_uncompress_elliptic_curve_EXIT1;
   }

   if ((sz_tmp=(2*sz_tmp+1))>output_sz) {
      err=602;
      goto f_uncompress_elliptic_curve_EXIT1;
   }
/*
   if ((public_key[0]!=0x02)&&(public_key[0]!=0x03)) {
      err=603;
      goto f_uncompress_elliptic_curve_EXIT1;
   }
*/
   output[0]=0x04;
   memcpy(&output[1], &public_key[1], sz_tmp2);

   if (olen)
      *olen=sz_tmp;

   mbedtls_mpi_init(_RR=(mbedtls_mpi *)(buffer+sizeof(mbedtls_ecdsa_context)));
   mbedtls_mpi_init(X=&_RR[1]);
   mbedtls_mpi_init(R=&X[1]);
   mbedtls_mpi_init(N=&R[1]);

   if (mbedtls_mpi_read_binary(X, &public_key[1], sz_tmp2)) {
      err=604;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (mbedtls_mpi_mul_mpi(R, X, X)) {
      err=605;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (&ecdsa_ctx->grp.A.p) {
      if (mbedtls_mpi_add_mpi(R, R, &ecdsa_ctx->grp.A)) {
         err=606;
         goto f_uncompress_elliptic_curve_EXIT2;
      }
   } else if (mbedtls_mpi_sub_int(R, R, 3)) {
      err=607;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (mbedtls_mpi_mul_mpi(R, R, X)) {
      err=608;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (mbedtls_mpi_add_mpi(R, R, &ecdsa_ctx->grp.B)) {
      err=609;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (mbedtls_mpi_add_int(N, &ecdsa_ctx->grp.P, 1)) {
      err=610;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (mbedtls_mpi_shift_r(N, 2)) {
      err=611;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (mbedtls_mpi_exp_mod(R, R, N, &ecdsa_ctx->grp.P, _RR)) {
      err=612;
      goto f_uncompress_elliptic_curve_EXIT2;
   }

   if (mbedtls_mpi_get_bit(R, 0)^(public_key[0]==0x03))
      if (mbedtls_mpi_sub_mpi(R, &ecdsa_ctx->grp.P, R)) {
         err=613;
         goto f_uncompress_elliptic_curve_EXIT2;
      }

   err=mbedtls_mpi_write_binary(R, output+public_key_sz, sz_tmp2);

f_uncompress_elliptic_curve_EXIT2:
   mbedtls_mpi_free(N);
   mbedtls_mpi_free(R);
   mbedtls_mpi_free(X);
   mbedtls_mpi_free(_RR);

f_uncompress_elliptic_curve_EXIT1:
   mbedtls_ecdsa_free(ecdsa_ctx);
   memset(buffer, 0, UNCOMPRESS_BUFFER_SZ);
   free(buffer);

   return err;
}

uint8_t *f_ripemd160(const uint8_t *data, size_t data_sz)
{
   static uint8_t hs[20];

   if (mbedtls_ripemd160_ret((const unsigned char *)data, data_sz, (unsigned char *)hs))
      return NULL;

   return hs;
}

char *f_get_entropy_name(uint32_t val)
{

   switch (val) {

      case (uint32_t)1:
      case (uint32_t)'1':
      case (uint32_t)F_ENTROPY_TYPE_PARANOIC:
         return "F_ENTROPY_TYPE_PARANOIC";

      case (uint32_t)2:
      case (uint32_t)'2':
      case (uint32_t)F_ENTROPY_TYPE_EXCELENT:
         return "F_ENTROPY_TYPE_EXCELENT";

      case (uint32_t)3:
      case (uint32_t)'3':
      case (uint32_t)F_ENTROPY_TYPE_GOOD:
         return "F_ENTROPY_TYPE_GOOD";

      case (uint32_t)4:
      case (uint32_t)'4':
      case (uint32_t)F_ENTROPY_TYPE_NOT_ENOUGH:
         return "F_ENTROPY_TYPE_NOT_ENOUGH";

      case (uint32_t)5:
      case (uint32_t)'5':
      case (uint32_t)F_ENTROPY_TYPE_NOT_RECOMENDED:
         return "F_ENTROPY_TYPE_NOT_RECOMENDED";

   }

   return NULL;

}

uint32_t f_sel_to_entropy_level(int sel)
{

   if (sel&0x30)
      sel-=0x30;

   switch (sel) {

      case 1: return F_ENTROPY_TYPE_PARANOIC;
      case 2: return F_ENTROPY_TYPE_EXCELENT;
      case 3: return F_ENTROPY_TYPE_GOOD;
      case 4: return F_ENTROPY_TYPE_NOT_ENOUGH;
      case 5: return F_ENTROPY_TYPE_NOT_RECOMENDED;

   }

   return 0;

}
#ifdef F_ESP32
int IRAM_ATTR f_str_to_hex(uint8_t *hex_stream, char *str)
#else
int f_str_to_hex(uint8_t *hex_stream, char *str)
#endif
{

   char ch;
   size_t len=strlen(str);
   size_t i;

   for (i=0;i<len;i++) {
      ch=str[i];

      if (ch>'f')
         return 1;

      if (ch<'0')
         return 2;

      ch-='0';

      if (ch>9) {
         if (ch&0x30) {

            if ((ch&0x30)==0x20)
               return 4;

            ch&=0x0F;

            ch+=9;

            if (ch<10)
               return 5;
            if (ch>15)
               return 6;

         } else
            return 3;
      }

      (i&1)?(hex_stream[i>>1]|=(uint8_t)ch):(hex_stream[i>>1]=(uint8_t)(ch<<4));
   }

   return 0;

}
// success if zero, fail if nonzero
//inline int f_is_integer(char *value, size_t value_sz) { return f_is_integer_util(value, value_sz, 10); }
#define F_CONV_TO_DOUBLE_PREC (size_t)15
int f_convert_to_double(double *val, const char *value)
{

   int err=0;
   double d;
   size_t value_tmp;
   char *p, *k, *buf;
//3 => '0', '+/-' and '.'
   if ((value_tmp=strnlen(value, F_CONV_TO_DOUBLE_PREC+3))==(F_CONV_TO_DOUBLE_PREC+3))
      return 27;

   if (!value_tmp)
      return 28;

   if (!(buf=malloc(++value_tmp)))
      return 29;

   strncpy(p=buf, value, value_tmp);

   if ((buf[0]=='-')||(buf[0]=='+')) {
      value_tmp--;
      p++;
   }

   if ((k=strrchr(p, '.'))) {
      *k=0;
      value_tmp--;
      strcat(p, ++k);
   }

   if (value_tmp>(F_CONV_TO_DOUBLE_PREC+1)) {

      err=30;

      goto f_convert_to_double_EXIT1;

   }

   if (!f_is_integer(p, value_tmp)) {

      err=31;

      goto f_convert_to_double_EXIT1;

   }

   if ((d=strtod(value, NULL))==0.0) {

      if (errno==ERANGE)
         err=5;
      else if (errno)
         err=7;

   }

   if (err==0)
      *val=d;

f_convert_to_double_EXIT1:
   free(buf);

   return err;

}

// success if zero, fail if nonzero
int f_convert_to_long_int_util(unsigned long int *val, char *value, size_t value_sz, int base)
{
   int err;
   unsigned long int value_tmp;

   if (!f_is_integer_util(value, value_sz, base))
      return 1;

   err=0;

   if ((value_tmp=strtoul(value, NULL, base))==0) {

      if (errno==EINVAL)
         err=2;
      else if (errno==ERANGE)
         err=3;

   }

   if (err==0)
      *val=value_tmp;

   return err;

}

inline int f_convert_to_long_int0x(unsigned long int *val, char *value, size_t value_sz) { return f_convert_to_long_int_util(val, value, value_sz, 16); }
inline int f_convert_to_long_int(unsigned long int *val, char *value, size_t value_sz) { return f_convert_to_long_int_util(val, value, value_sz, 10); }
inline int f_convert_to_long_int0(unsigned long int *val, char *value, size_t value_sz) { return f_convert_to_long_int_util(val, value, value_sz, 8); }
inline int f_convert_to_long_int_std(unsigned long int *val, char *value, size_t value_sz) { return f_convert_to_long_int_util(val, value, value_sz, 0); }

inline int f_convert_to_unsigned_int(unsigned int *val, char *value, size_t value_sz) {

   unsigned long int val_tmp;
   int err;

   if ((err=f_convert_to_long_int(&val_tmp, value, value_sz)))
      return err;

   *val=(unsigned int)val_tmp;

   return err;

}

inline int f_convert_to_unsigned_int0x(unsigned int *val, char *value, size_t value_sz) {

   unsigned long int val_tmp;
   int err;

   if ((err=f_convert_to_long_int0x(&val_tmp, value, value_sz)))
      return err;

   *val=(unsigned int)val_tmp;

   return err;

}

inline int f_convert_to_unsigned_int0(unsigned int *val, char *value, size_t value_sz) {

   unsigned long int val_tmp;
   int err;

   if ((err=f_convert_to_long_int0(&val_tmp, value, value_sz)))
      return err;

   *val=(unsigned int)val_tmp;

   return err;

}

inline int f_convert_to_unsigned_int_std(unsigned int *val, char *value, size_t value_sz) {

   unsigned long int val_tmp;
   int err;

   if ((err=f_convert_to_long_int_std(&val_tmp, value, value_sz)))
      return err;

   *val=(unsigned int)val_tmp;

   return err;

}

uint32_t crc32_init(unsigned char *p, size_t len, uint32_t crcinit)
{
   uint32_t crc;

   extern const uint32_t crc32tab[256] asm("_binary_fcrc32data_dat_start");

   crc=crcinit^0xFFFFFFFF;

   for (;len--;p++)
      crc=((crc>>8)&0x00FFFFFF)^crc32tab[(crc^(*p))&0xFF];

   return crc^0xFFFFFFFF;

}

#ifndef F_ESP32

inline void f_random_attach(rnd_fn fn) {__rnd_fn=fn;}

inline void f_random(void *random, size_t random_sz)
{

   if (__rnd_fn)
      __rnd_fn(random, random_sz);

}

inline void *f_is_random_attached() { return (void *)__rnd_fn; }
inline void f_random_detach() { __rnd_fn=NULL; }

int get_console_passwd(char *pass, size_t pass_sz)
{

   struct termios oflags, nflags;
   int err, i;

   tcgetattr(fileno(stdin), &oflags);
   nflags=oflags;
   nflags.c_lflag&=~ECHO;
   nflags.c_lflag|=ECHONL;

   if (tcsetattr(fileno(stdin), TCSADRAIN, &nflags)) return 10;

   if (!fgets(pass, pass_sz, stdin)) {

      err=11;
      goto PASS_ERR;

   }

   err=12;

   for (i=0;i<pass_sz;i++)
      if ((pass[i])==0x0A) {

         if (i) {
            pass[i]=0;
            err=0;
         } else
            err=13;

         break;

      }

PASS_ERR:

   if (tcsetattr(fileno(stdin), TCSANOW, &oflags)) return 14;

   return err;

}

int f_get_char_no_block(int mode)
{

   int err;

   struct termios oflags, nflags;

   tcgetattr(fileno(stdin), &oflags);
   nflags=oflags;
   nflags.c_lflag&=~ICANON;
   (mode&F_GET_CH_MODE_NO_ECHO)?(nflags.c_lflag&=(~ECHO)):(nflags.c_lflag|=ECHO);

   if (tcsetattr(fileno(stdin), TCSADRAIN, &nflags)) return -15;

   if (mode&F_GET_CH_MODE_ANY_KEY) err=getc(stdin);
   else {

      mode&=0x0000FFFF;
      while ((err=getc(stdin))^mode);

   }

   if (tcsetattr(fileno(stdin), TCSANOW, &oflags)) return -16;

   return err;

}

#endif

