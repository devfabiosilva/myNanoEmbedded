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

int f_verify_system_entropy_begin()
{
   if (!__entropy_val) {
      __entropy_val=malloc(256*sizeof(uint32_t));

      if (!__entropy_val)
         return 5001;

   }

   if (!__rand_data) {
      __rand_data=malloc(F_LOG_MAX);

     if (!__rand_data)
        return 5002;

   }

   return 0;
}

void f_verify_system_entropy_finish()
{
   if (__rand_data) {
      free(__rand_data);
      __rand_data=NULL;
   }

   if (__entropy_val) {
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

uint8_t *f_sha256_digest(uint8_t *msg, size_t size)
{
    static uint8_t result256sum[32];

    mbedtls_sha256_context sha256;

    mbedtls_sha256_init(&sha256);

    mbedtls_sha256_starts_ret(&sha256, 0);

    mbedtls_sha256_update_ret(&sha256, msg, size);

    mbedtls_sha256_finish(&sha256, result256sum);

    mbedtls_sha256_free(&sha256);

    return result256sum;
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

