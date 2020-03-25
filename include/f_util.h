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
 * @param [in] password Password string
 * @param [in] n Max buffer string permitted to store password including NULL char
 * @param [in] min Minimum size allowed in password string
 * @param [in] max Maximum size allowed in password
 * @param [in] must_have Must have a type:
 *     - F_PASS_MUST_HAVE_AT_LEAST_NONE Not need any special characters or number
 *     - F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER Must have at least one number
 *     - F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL Must have at least one symbol
 *     - F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE Must have at least one upper case
 *
 * <b>Return values:</b>
 *
 * - <i>0 (zero):</i> If password is passed in the test<br>
 * - <i>F_PASS_IS_OUT_OVF:</i> If password lenght exceeds <i>n</i> value<br>
 * - <i>F_PASS_IS_TOO_SHORT:</i> If password length is less than <i>min</i> value<br>
 * - <i>F_PASS_IS_TOO_LONG:</i> If password length is greater tham <i>m</i> value<br>
 * - <i>F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE:</i> If password is required in <i>must_have</i> type upper case characters
 * - <i>F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL:</i> If password is required in <i>must_have</i> type to have symbol(s)
 * - <i>F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER:</i> if password is required in <i>must_have</i> type to have number(s)
 *
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
/**
 * @def F_ENTROPY_TYPE_PARANOIC
 * @brief Type of the very excelent entropy used for verifier. Very slow
 */
#define F_ENTROPY_TYPE_PARANOIC (uint32_t)1477682819

//#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1475885281
/**
 * @def F_ENTROPY_TYPE_EXCELENT
 * @brief Type of the excelent entropy used for verifier. Slow
 */
#define F_ENTROPY_TYPE_EXCELENT (uint32_t)1476885281

//#define F_ENTROPY_TYPE_GOOD (uint32_t)1471531015
/**
 * @def F_ENTROPY_TYPE_GOOD
 * @brief Type of the good entropy used for verifier. Not so slow
 */
#define F_ENTROPY_TYPE_GOOD (uint32_t)1472531015

//#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1470001808
/**
 * @def F_ENTROPY_TYPE_NOT_ENOUGH
 * @brief Type of the moderate entropy used for verifier. Fast
 */
#define F_ENTROPY_TYPE_NOT_ENOUGH (uint32_t)1471001808

//#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1469703345
/**
 * @def F_ENTROPY_TYPE_NOT_RECOMENDED
 * @brief Type of the not recommended entropy used for verifier. Very fast
 */
#define F_ENTROPY_TYPE_NOT_RECOMENDED (uint32_t)1470003345

/**
 * @def ENTROPY_BEGIN
 * @brief Begins and prepares a entropy function
 * @see f_verify_system_entropy()
 */
#define ENTROPY_BEGIN f_verify_system_entropy_begin();

/**
 * @def ENTROPY_END
 * @brief Ends a entropy function
 * @see f_verify_system_entropy()
 */
#define ENTROPY_END f_verify_system_entropy_finish();

/**
 * @def F_PASS_MUST_HAVE_AT_LEAST_NONE
 * @brief Password does not need any criteria to pass
 */
#define F_PASS_MUST_HAVE_AT_LEAST_NONE (int)0

/**
 * @def F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER
 * @brief Password must have at least one number
 */
#define F_PASS_MUST_HAVE_AT_LEAST_ONE_NUMBER (int)1

/**
 * @def F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL
 * @brief Password must have at least one symbol
 */
#define F_PASS_MUST_HAVE_AT_LEAST_ONE_SYMBOL (int)2

/**
 * @def F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE
 * @brief Password must have at least one upper case
 */
#define F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE (int)4

/**
 * @def F_PASS_IS_TOO_LONG
 * @brief Password is too long
 */
#define F_PASS_IS_TOO_LONG (int)256

/**
 * @def F_PASS_IS_TOO_SHORT
 * @brief Password is too short
 */
#define F_PASS_IS_TOO_SHORT (int)512

/**
 * @def F_PASS_IS_OUT_OVF
 * @brief Password is overflow and cannot be stored
 */
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

/**
 * @typedef rnd_fn
 * @brief Pointer caller for random function
 */
typedef void (*rnd_fn)(void *, size_t);

/**
 * @fn void f_random_attach(rnd_fn fn)
 * @brief Attachs a function to be called by <i>f_random()</i>
 * @param [in] fn A function to be called
 *
 * @see rnd_fn
 */
void f_random_attach(rnd_fn);

/**
 * @fn void f_random(void *random, size_t random_sz)
 * @brief Random function to be called to generate a <i>random</i> data with <i>random_sz</i>
 * @param [out] random Random data to be parsed
 * @param [in] random_sz Size of random data to be filled
 *
 * @see f_random_attach()
 */
void f_random(void *, size_t);

#endif

#ifdef __cplusplus
}
#endif