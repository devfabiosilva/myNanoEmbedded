/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

/**
 * @file
 * @brief This ABI is a utility for myNanoEmbedded library and sub routines are implemented here.
 */

#include <stdint.h>
#include "mbedtls/sha256.h"
#include "mbedtls/aes.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef F_DOC_SKIP

 #define F_LOG_MAX 8*256

#endif

#ifdef F_ESP32

 #define F_WDT_MAX_ENTROPY_TIME 2*120
 #define F_WDT_PANIC true
 #define F_WDT_MIN_TIME 20//4

#endif

/**
 * @fn int f_verify_system_entropy(uint32_t type, void *rand, size_t rand_sz, int turn_on_wdt)
 * @brief Take a random number generator function and returns random value only if randomized data have a desired entropy value
 * @param [in] type Entropy type. Entropy type values are:
 *     - F_ENTROPY_TYPE_PARANOIC Highest level entropy recommended for generate a Nano SEED with a paranoic entropy. Very slow
 *     - F_ENTROPY_TYPE_EXCELENT Gives a very excellent entropy for generating Nano SEED. Slow
 *     - F_ENTROPY_TYPE_GOOD Good entropy type for generating Nano SEED. Normal.
 *     - F_ENTROPY_TYPE_NOT_ENOUGH Moderate entropy for generating Nano SEED. Usually fast to create a temporary Nano SEED. Fast
 *     - F_ENTROPY_TYPE_NOT_RECOMENDED Fast but not recommended for generating Nano SEED.
 * @param [out] rand Random data with a satisfied type of entropy
 * @param [in] rand_sz Size of random data output
 * @param [in] turn_on_wdt For ESP32, Arduino platform and other microcontrollers only. Turns on/off WATCH DOG (0: OFF, NON ZERO: ON).
 *     For Raspberry PI and Linux native is ommited.
 *
 * @retval 0: On Success, otherwise Error
 */
int f_verify_system_entropy(uint32_t, void *, size_t, int);

/**
 * @fn int f_pass_must_have_at_least(char *password, size_t n, size_t min, size_t max, int must_have)
 * @brief Checks if a given password has enought requirements to be parsed to a function
 * @param 
 */
int f_pass_must_have_at_least(char *, size_t, size_t, size_t, int);

#ifndef F_DOC_SKIP

int f_verify_system_entropy_begin();
void f_verify_system_entropy_finish();
int f_file_exists(char *);
int f_find_str(size_t *, char *, size_t, char *);
int f_find_replace(char *, size_t *, size_t, char *, size_t, char *, char *);
int f_is_integer(char *, size_t);
int is_filled_with_value(uint8_t *, size_t, uint8_t);

#endif

//#define F_ENTROPY_TYPE_PARANOIC (uint32_t)1476682819
#define F_ENTROPY_TYPE_PARANOIC (uint32_t)1477682819
//#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1475885281
#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1476885281
//#define F_ENTROPY_TYPE_GOOD (uint32_t)1471531015
#define F_ENTROPY_TYPE_GOOD (uint32_t)1472531015
//#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1470001808
#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1471001808
//#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1469703345
#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1470003345

#define ENTROPY_BEGIN f_verify_system_entropy_begin();
#define ENTROPY_END f_verify_system_entropy_finish();

#define F_PASS_MUST_HAVE_AT_LEAST_NONE (int)0
#define F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER (int)1
#define F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL (int)2
#define F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE (int)4
#define F_PASS_IS_TOO_LONG (int)256
#define F_PASS_IS_TO_SHORT (int)512
#define F_PASS_IS_OUT_OVF (int)768

#ifndef F_DOC_SKIP

 #define F_PBKDF2_ITER_SZ 2*4096

typedef enum f_pbkdf2_err_t {
    F_PBKDF2_RESULT_OK=0,
    F_PBKDF2_ERR_CTX=95,
    F_PBKDF2_ERR_PKCS5,
    F_PBKDF2_ERR_INFO_SHA
} f_pbkdf2_err;

typedef enum f_aes_err {
    F_AES_RESULT_OK=0,
    F_AES_ERR_ENCKEY=30,
    F_AES_ERR_DECKEY,
    F_AES_ERR_MALLOC,
    F_AES_UNKNOW_DIRECTION,
    F_ERR_ENC_DECRYPT_FAILED
} f_aes_err;

char *fhex2strv2(char *, const void *, size_t, int);
uint8_t *f_sha256_digest(uint8_t *, size_t);
f_pbkdf2_err f_pbkdf2_hmac(unsigned char *, size_t, unsigned char *, size_t, uint8_t *);
f_aes_err f_aes256cipher(uint8_t *, uint8_t *, void *, size_t, void *, int);

#endif

#ifndef F_ESP32

typedef void (*rnd_fn)(void *, size_t);

void f_random_attach(rnd_fn);
void f_random(void *, size_t);

#endif

#ifdef __cplusplus
}
#endif
