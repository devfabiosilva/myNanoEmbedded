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
 #define LICENSE \
"MIT License\n\n\
Copyright (c) 2019 Fábio Pereira da Silva\n\n\
Permission is hereby granted, free of charge, to any person obtaining a copy\n\
of this software and associated documentation files (the \"Software\"), to deal\n\
in the Software without restriction, including without limitation the rights\n\
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n\
copies of the Software, and to permit persons to whom the Software is\n\
furnished to do so, subject to the following conditions:\n\n\
The above copyright notice and this permission notice shall be included in all\n\
copies or substantial portions of the Software.\n\n\
THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n\
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n\
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n\
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n\
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n\
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n\
SOFTWARE.\n\n\n"

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
 * @brief This implementation is based on topic in <a href="https://web.mit.edu/16.unified/www/FALL/thermodynamics/notes/node56.html">Definition 7.12</a> in MIT opencourseware (7.3 A Statistical Definition of Entropy - 2005)<br> Many thanks to <b>Professor Z. S. Spakovszky</b> for this amazing topic
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
 *     - F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE Must have at least one lower case
 *
 * <b>Return values:</b>
 *
 * - <i>0 (zero):</i> If password is passed in the test<br>
 * - <i>F_PASS_IS_OUT_OVF:</i> If password lenght exceeds <i>n</i> value<br>
 * - <i>F_PASS_IS_TOO_SHORT:</i> If password length is less than <i>min</i> value<br>
 * - <i>F_PASS_IS_TOO_LONG:</i> If password length is greater tham <i>m</i> value<br>
 * - <i>F_PASS_MUST_HAVE_AT_LEAST_ONE_UPPER_CASE:</i> If password is required in <i>must_have</i> type upper case characters
 * - <i>F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE:</i> If password is required in <i>must_have</i> type lower case characters
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
 * @def F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE
 * @brief Password must have at least one lower case
 */
#define F_PASS_MUST_HAVE_AT_LEAST_ONE_LOWER_CASE (int)8

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
#define F_PASS_IS_OUT_OVF (int)1024//768

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

typedef enum f_md_hmac_sha512_t {
   F_HMAC_SHA512_OK = 0,
   F_HMAC_SHA512_MALLOC = 304,
   F_HMAC_SHA512_ERR_INFO,
   F_HMAC_SHA512_ERR_SETUP,
   F_HMAC_SHA512_DIGEST_ERROR
} f_md_hmac_sha512;

char *fhex2strv2(char *, const void *, size_t, int);
uint8_t *f_sha256_digest(uint8_t *, size_t);
f_pbkdf2_err f_pbkdf2_hmac(unsigned char *, size_t, unsigned char *, size_t, uint8_t *);
f_aes_err f_aes256cipher(uint8_t *, uint8_t *, void *, size_t, void *, int);

#endif

/**
 * @fn int f_passwd_comp_safe(char *pass1, char *pass2, size_t n, size_t min, size_t max)
 * @brief Compares two passwords values with safe buffer
 * @param [in] pass1 First password to compare with <i>pass2</i>
 * @param [in] pass2 Second password to compare with <i>pass1</i>
 * @param [in] n Size of Maximum buffer of both <i>pass1</i> and <i>pass2</i>
 * @param [in] min Minimun value of both <i>pass1</i> and <i>pass2</i>
 * @param [in] max Maximum value of both <i>pass1</i> and <i>pass2</i>
 *
 * @retval 0: If <i>pass1</i> is equal to <i>pass2</i>, otherwise value is less than 0 (zero) if password does not match
 */
int f_passwd_comp_safe(char *, char *, size_t, size_t, size_t);

/**
 * @fn char *f_get_entropy_name(uint32_t val)
 * @brief Returns a entropy name given a index/ASCII index or entropy value
 * @param [in] val Index/ASCII index or entropy value
 *
 * <b>Return values:</b>
 *
 * - <i>NULL</i> If no entropy index/ASCII/entropy found in <i>val</i><br>
 * - <i>F_ENTROPY_TYPE_*</i> name if found in index/ASCII or entropy value
 */
char *f_get_entropy_name(uint32_t);

/**
 * @fn uint32_t f_sel_to_entropy_level(int sel)
 * @brief Return a given entropy number given a number encoded ASCII or index number
 * @param [in] sel ASCII or index value
 *
 * <b>Return values:</b>
 *
 * - <i>0 (zero):</i> If no entropy number found in <i>sel</i><br>
 * - <i>F_ENTROPY_TYPE_PARANOIC</i>
 * - <i>F_ENTROPY_TYPE_EXCELENT</i>
 * - <i>F_ENTROPY_TYPE_GOOD</i>
 * - <i>F_ENTROPY_TYPE_NOT_ENOUGH</i>
 * - <i>F_ENTROPY_TYPE_NOT_RECOMENDED</i>
 */
uint32_t f_sel_to_entropy_level(int);

/**
 * @fn int f_str_to_hex(uint8_t *hex_stream, char *str)
 * @brief Converts a <i>str</i> string buffer to raw <i>hex_stream</i> value stream
 * @param [out] hex Raw hex value
 * @param [in] str String buffer terminated with NULL char
 *
 * @retval 0: On Success, otherwise Error
 */
int f_str_to_hex(uint8_t *, char *);

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
 * @see rnd_fn()
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

/**
 * @fn int get_console_passwd(char *pass, size_t pass_sz)
 * @brief Reads a password from console
 * @param [out] pass Password to be parsed to pointer
 * @param [in] pass_sz Size of buffer <i>pass</i>
 *
 * @retval 0: On Success, otherwise Error
 */
int get_console_passwd(char *, size_t);

/**
 * @def F_GET_CH_MODE_NO_ECHO
 * @see f_get_char_no_block()
 */
#define F_GET_CH_MODE_NO_ECHO (int)(1<<16)

/**
 * @def F_GET_CH_MODE_ANY_KEY
 * @see f_get_char_no_block()
 */
#define F_GET_CH_MODE_ANY_KEY (int)(1<<17)

/**
 * @fn int f_get_char_no_block(int mode)
 * @brief Reads a char from console. Waits a char and returns its value
 * @param [in] mode Mode and/or character to be returned
 *     - <i>F_GET_CH_MODE_NO_ECHO</i> No echo is on the console string
 *     - <i>F_GET_CH_MODE_ANY_KEY</i> Returns any key pressed<br><br>
 *
 *<li><strong>Example:</strong>
 *   @code{.c}
 *       key=f_get_char_no_block(F_GET_CH_MODE_NO_ECHO|'c'); // Waits 'c' char key and returns value 0x00000063 without echo 'c' on the screen
 *   @endcode
 *</li>
 *
 * @retval key code: On Success, Negative value on error
 */
int f_get_char_no_block(int);

#endif

/**
 * @fn int f_convert_to_long_int(unsigned long int *val, char *value, size_t value_sz)
 * @brief Converts a string value to unsigned long int
 * @param [out] val Value stored in a unsigned long int variable
 * @param [in] value Input value to be parsed to unsigned long int
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_unsigned_int()
 */
int f_convert_to_long_int(unsigned long int *, char *, size_t);


/**
 * @fn int f_convert_to_unsigned_int(unsigned int *val, char *value, size_t value_sz)
 * @brief Converts a string value to unsigned int
 * @param [out] val Value stored in a unsigned int variable
 * @param [in] value Input value to be parsed to unsigned int
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_long_int()
 */
int f_convert_to_unsigned_int(unsigned int *, char *, size_t);

/**
 * @fn int f_convert_to_long_int0x(unsigned long int *val, char *value, size_t value_sz)
 * @brief Converts a hex value in ASCII string to unsigned long int
 * @param [out] val Value stored in a unsigned long int variable
 * @param [in] value Input value to be parsed to unsigned long int
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_long_int0()
 */
int f_convert_to_long_int0x(unsigned long int *, char *, size_t);

/**
 * @fn int f_convert_to_long_int0(unsigned long int *val, char *value, size_t value_sz)
 * @brief Converts a octal value in ASCII string to unsigned long int
 * @param [out] val Value stored in a unsigned long int variable
 * @param [in] value Input value to be parsed to unsigned long int
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_long_int0x()
 */
int f_convert_to_long_int0(unsigned long int *, char *, size_t);

/**
 * @fn int f_convert_to_long_int_std(unsigned long int *val, char *value, size_t value_sz)
 * @brief Converts a actal/decimal/hexadecimal into ASCII string to unsigned long int
 * @param [out] val Value stored in a unsigned long int variable
 * @param [in] value Input value to be parsed to unsigned long int
 *    - If a string contains only numbers, it will be parsed to unsigned long int decimal
 *    - If a string begins with 0 it will be parsed to octal EX.: 010(octal) = 08(decimal)
 *    - If a string contais 0x or 0X it will be parsed to hexadecimal. EX.: 0x10(hexadecimal) = 16 (decimal)
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_long_int()
 */
int f_convert_to_long_int_std(unsigned long int *, char *, size_t);

/**
 * @fn void *f_is_random_attached()
 * @brief Verifies if system random function is attached in myNanoEmbedded API
 *
 * @retval NULL: if not attached, Otherwise returns the pointer of random number genarator function
 * @see f_random_attach()
 */
void *f_is_random_attached();

/**
 * @fn void f_random_detach()
 * @brief Detaches system random numeber genarator from myNanoEmbedded API
 *
 * @see f_random_attach()
 */
void f_random_detach();

/**
 * @fn int f_convert_to_unsigned_int0x(unsigned int *val, char *value, size_t value_sz)
 * @brief Converts a hex value in ASCII string to unsigned int
 * @param [out] val Value stored in a unsigned int variable
 * @param [in] value Input value to be parsed to unsigned int
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_unsigned_int0()
 */
int f_convert_to_unsigned_int0x(unsigned int *val, char *value, size_t value_sz);

/**
 * @fn int f_convert_to_unsigned_int0(unsigned int *val, char *value, size_t value_sz)
 * @brief Converts a octal value in ASCII string to unsigned int
 * @param [out] val Value stored in a unsigned int variable
 * @param [in] value Input value to be parsed to unsigned int
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_unsigned_int0x()
 */
int f_convert_to_unsigned_int0(unsigned int *val, char *value, size_t value_sz);

/**
 * @fn int f_convert_to_unsigned_int_std(unsigned int *val, char *value, size_t value_sz)
 * @brief Converts a actal/decimal/hexadecimal into ASCII string to unsigned int
 * @param [out] val Value stored in a unsigned int variable
 * @param [in] value Input value to be parsed to unsigned int
 *    - If a string contains only numbers, it will be parsed to unsigned int decimal
 *    - If a string begins with 0 it will be parsed to octal EX.: 010(octal) = 08(decimal)
 *    - If a string contais 0x or 0X it will be parsed to hexadecimal. EX.: 0x10(hexadecimal) = 16 (decimal)
 * @param [in] value_sz Max size allowed in <i>value</i> string.
 *
 * @retval 0: On Success, Otherwise error
 * @see f_convert_to_unsigned_int()
 */
int f_convert_to_unsigned_int_std(unsigned int *val, char *value, size_t value_sz);

/**
 * @fn int f_convert_to_double(double *val, const char *value)
 * @brief Convert any valid number im <i>value</i> and converts it to double <i>val</i>
 *
 * @param [out] val Value converted to double
 * @param [in] value Value in string to be converted
 *
 * @retval 0: On Success, Otherwise error
 */
int f_convert_to_double(double *, const char *);

/**
 * @fn uint32_t crc32_init(unsigned char *p, size_t len, uint32_t crcinit)
 * @brief Performs a CRC32 of a given data
 *
 * @param [in] p Pointer of the data
 * @param [in] len Size of data in pointer <i>p</i>
 * @param [in] crcinit Init vector of the CRC32
 *
 * @retval CRC32 hash
 */
uint32_t crc32_init(unsigned char *, size_t, uint32_t);
//
int f_reverse(unsigned char *, size_t);
f_md_hmac_sha512 f_hmac_sha512(unsigned char *, const unsigned char *, size_t, const unsigned char *, size_t);

#ifdef __cplusplus
}
#endif
