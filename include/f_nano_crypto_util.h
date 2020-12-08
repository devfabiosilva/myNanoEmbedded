/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdint.h>
#include <f_util.h>
#include <f_bitcoin.h>

#ifndef F_DOC_SKIP

 #ifdef F_XTENSA

  #ifndef F_ESP32
   #define F_ESP32
  #endif

  #include "esp_system.h"

 #endif

 #include "sodium/crypto_generichash.h"
 #include "sodium/crypto_sign.h"
 #include "sodium.h"

 #ifdef F_ESP32

  #include "sodium/private/curve25519_ref10.h"

 #else

  #include "sodium/private/ed25519_ref10.h"

  #define ge_p3 ge25519_p3
  #define sc_reduce sc25519_reduce
  #define sc_muladd sc25519_muladd
  #define ge_scalarmult_base ge25519_scalarmult_base
  #define ge_p3_tobytes ge25519_p3_tobytes

 #endif

#endif

/**
 * @file
 * @brief This API Integrates Nano Cryptocurrency to low computational devices
 * @mainpage Overview
 *
 * @details <a href="https://github.com/devfabiosilva/myNanoEmbedded"><i>myNanoEmbedded</i></a> is
 * a lightweight C library of source files that integrates
 * <a href="https://nano.org">Nano Cryptocurrency</a> to low complexity computational devices to send/receive digital money
 * to anywhere in the world with fast trasnsaction and with a small fee by delegating a Proof of Work 
 * with your choice:
 *
 * - DPoW (Distributed Proof of Work)
 * - P2PoW (a Descentralized P2P Proof of Work)
 *
 * ## API features
 *
 * - Attaches a random function to TRNG hardware (if available)
 * - Self entropy verifier to ensure excelent TRNG or PRNG entropy
 * - Creates a encrypted by password your stream or file to store your Nano SEED
 * - Bip39 and Brainwallet support
 * - Convert raw data to Base32
 * - Parse SEED and Bip39 to JSON
 * - Sign a block using Blake2b hash with Ed25519 algorithm
 * - ARM-A, ARM-M, Thumb, Xtensa-LX6 and IA64 compatible
 * - Linux desktop, Raspberry PI, ESP32 and Olimex A20 tested platforms
 * - Communication over <a href="https://github.com/devfabiosilva/FIOT/tree/master/DPoW_FIOT_SERVER/Python">Fenix protocol</a> bridge over TLS
 * - Libsodium and mbedTLS libraries with smaller resources and best performance
 * - Optmized for size and speed
 * - Non static functions (all data is cleared before processed for security)
 * - Fully written in C for maximum performance and portability
 *
 * ## To add this API in your project you must first:
 *
 * <ol>
 *   <li>Download the latest version.
 * 
 *   @code{.sh}
 *   git clone https://github.com/devfabiosilva/myNanoEmbedded.git --recurse-submodules
 *   @endcode
 *   </li>
 *   <li>Include the main library files in the client application.
 *   @code{.c}
 *   #include "f_nano_crypto_util.h"
 *   @endcode
 *   </li>
 * </ol>
 *
 * ## Initialize API
 * | Function | Description |
 * | --- | --- |
 * | f_random_attach() | Initializes the PRNG or TRNG to be used in this API |
 *
 * ## Transmit/Receive transactions
 * To transmit/receive your transaction you must use <a href="https://github.com/devfabiosilva/FIOT/tree/master/DPoW_FIOT_SERVER/Python">Fenix</a> protocol
 * to stabilish a DPoW/P2PoW support
 *
 * ## Examples using platforms
 * The repository has some examples with most common embedded and Linux systems
 *
 * - <a href="../../../../examples/native_linux">Native Linux</a>
 * - <a href="../../../../examples/rpi">Raspberry Pi</a>
 * - <a href="../../../../examples/esp32">ESP32</a>
 * - <a href="../../../../examples/olimexa20">Olimex A20</a>
 * - <a href="../../../../examples/stm">STM</a>
 *
 * ## Credits
 *
 * @author Fábio Pereira da Silva
 * @date Feb 2020
 * @version 1.0
 * @copyright License MIT <a href="https://github.com/devfabiosilva/myNanoEmbedded/blob/master/LICENSE">see here</a>
 *
 * ## References:
 *     [<a href="https://content.nano.org/whitepaper/Nano_Whitepaper_en.pdf">1</a>] - Colin LeMahieu - <i>Nano: A Feeless Distributed Cryptocurrency Network</i> - (2015)
 *
 *     [<a href="https://web.mit.edu/16.unified/www/FALL/thermodynamics/notes/node56.html">2</a>] - Z. S. Spakovszky - <i>7.3 A Statistical Definition of Entropy</i> - (2005) - NOTE: Entropy function for cryptography is implemented based on <a href="https://web.mit.edu/16.unified/www/FALL/thermodynamics/notes/node56.html">Definition (7.12)</a> of this amazing topic
 *
 *     [<a href="https://medium.com/@kaiquenunes/delegated-proof-of-work-d566870924d9">3</a>] - Kaique Anarkrypto - <i>Delegated Proof of Work</i> - (2019)
 *
 *     [<a href="https://docs.nano.org/commands/rpc-protocol/#node-rpcs">4</a>] - <a href="https://docs.nano.org/">docs.nano.org</a> - <i>Node RPCs documentation</i>
 */

#ifdef __cplusplus
extern "C" {
#endif


/**
 * @def F_NANO_POW_MAX_THREAD
 * @brief (desktop only) Number of threads for Proof of Work routines. Default 10
 */
#define F_NANO_POW_MAX_THREAD (size_t)10

#ifndef F_DOC_SKIP
 #ifdef F_ESP32
  #undef F_NANO_POW_MAX_THREAD
 #endif
#endif

/**
 * @def MAX_STR_NANO_CHAR
 * @brief Defines a max size of Nano char (70 bytes)
 */
#define MAX_STR_NANO_CHAR (size_t)70 //5+56+8+1

/**
 * @def PUB_KEY_EXTENDED_MAX_LEN
 * @brief Max size of public key (extended)
 */
#define PUB_KEY_EXTENDED_MAX_LEN (size_t)40

/**
 * @def NANO_PREFIX
 * @brief Nano prefix
 */
#define NANO_PREFIX "nano_"

/**
 * @def XRB_PREFIX
 * @brief XRB (old Raiblocks) prefix
 */
#define XRB_PREFIX "xrb_"

#ifdef F_ESP32
/**
 * @def BIP39_DICTIONARY
 * @brief Path to Bip39 dictionary file. File containing dictionary words must be 16 bytes aligned !
 * @brief Default name: "dictionary.dic"
 */
#define BIP39_DICTIONARY "/spiffs/dictionary.dic"
#else

 #ifndef F_DOC_SKIP
  #define BIP39_DICTIONARY_SAMPLE "../../dictionary.dic"
  #define BIP39_DICTIONARY "dictionary.dic"
 #endif

#endif

/**
 * @def NANO_ENCRYPTED_SEED_FILE
 * @brief Path to non deterministic encrypted file with password. File containing the SEED of the Nano wallets generated by TRNG (if available in your Hardware)
 * or PRNG. <br>
 * Default name: "nano.nse"
 */
#define NANO_ENCRYPTED_SEED_FILE "/spiffs/secure/nano.nse"

/**
 * @def NANO_PASSWD_MAX_LEN
 * @brief Password max length
 */
#define NANO_PASSWD_MAX_LEN (size_t)80

/**
 * @def STR_NANO_SZ
 * @brief String size of Nano encoded Base32 including NULL char
 */
#define STR_NANO_SZ (size_t)66// 65+1 Null included

/**
 * @def NANO_FILE_WALLETS_INFO
 * @brief Custom information file path about Nano SEED wallet stored in "walletsinfo.i"
 */
#define NANO_FILE_WALLETS_INFO "/spiffs/secure/walletsinfo.i"

/**
 * @def F_TOKEN
 * @brief Custom non deterministic token generation block for developing API's
 */
typedef uint8_t F_TOKEN[16];

/**
 * @typedef NANO_SEED
 * @brief Size of Nano SEED
 */
typedef uint8_t NANO_SEED[crypto_sign_SEEDBYTES];

/**
 * @typedef f_uint128_t
 * @brief 128 bit big number of Nano balance
 */
typedef uint8_t f_uint128_t[16];

#ifndef F_DOC_SKIP
 #define EXPORT_KEY_TO_CHAR_SZ (size_t)sizeof(NANO_SEED)+1
#endif

/**
 * @typedef NANO_PRIVATE_KEY
 * @brief Size of Nano Private Key.
 */
typedef uint8_t NANO_PRIVATE_KEY[sizeof(NANO_SEED)];

/**
 * @typedef NANO_PRIVATE_KEY_EXTENDED
 * @brief Size of Nano Private Key extended
 */
typedef uint8_t NANO_PRIVATE_KEY_EXTENDED[crypto_sign_ed25519_SECRETKEYBYTES];

/**
 * @typedef NANO_PUBLIC_KEY
 * @brief Size of Nano Public Key
 */
typedef uint8_t NANO_PUBLIC_KEY[crypto_sign_ed25519_PUBLICKEYBYTES];

/**
 * @typedef NANO_PUBLIC_KEY_EXTENDED
 * @brief Size of Public Key Extended
 */
typedef uint8_t NANO_PUBLIC_KEY_EXTENDED[PUB_KEY_EXTENDED_MAX_LEN];

/**
 * @typedef F_BLOCK_TRANSFER
 * @brief Nano signed block raw data defined in this <a href="https://docs.nano.org/integration-guides/the-basics/#self-signed-blocks">reference</a>
 * @see f_block_transfer_t
 *
 * @struct f_block_transfer_t
 * @brief Nano signed block raw data defined in this <a href="https://docs.nano.org/integration-guides/the-basics/#self-signed-blocks">reference</a>
 */
typedef struct f_block_transfer_t {
   /** Block preamble */
   uint8_t preamble[32];
   /** Account in raw binary data */
   uint8_t account[32];
   /** Previous block */
   uint8_t previous[32];
   /** Representative for current account */
   uint8_t representative[32];
   /** Big number 128 bit raw balance
   * @see #f_uint128_t
   */
   f_uint128_t balance;
   /** link or destination account */
   uint8_t link[32];
   /** Signature of the block */
   uint8_t signature[64];
   /** Internal use for this API */
   uint8_t prefixes;
   /** Internal use for this API */
   uint64_t work;
} __attribute__((packed)) F_BLOCK_TRANSFER;

#ifndef F_DOC_SKIP
 #define F_BLOCK_TRANSFER_SIGNABLE_SZ (size_t)(sizeof(F_BLOCK_TRANSFER)-64-sizeof(uint64_t)-sizeof(uint8_t))
#endif

/**
 * @typedef f_nano_err
 * @brief Error function enumerator
 * @see f_nano_err_t
 *
 * @enum f_nano_err_t
 */
typedef enum f_nano_err_t {
   /** SUCCESS */
   NANO_ERR_OK=0,
   /** Can not parse string big number */
   NANO_ERR_CANT_PARSE_BN_STR=5151,
   /** Fatal ERROR MALLOC */
   NANO_ERR_MALLOC,
   /** Can not parse big number factor */
   NANO_ERR_CANT_PARSE_FACTOR,
   /** Error multiplication MPI */
   NANO_ERR_MPI_MULT,
   /** Can not parse to block transfer */
   NANO_ERR_CANT_PARSE_TO_BLK_TRANSFER,
   /** Error empty string */
   NANO_ERR_EMPTY_STR,
   /** Can not parse value */
   NANO_ERR_CANT_PARSE_VALUE,
   /** Can not parse MPI to string */
   NANO_ERR_PARSE_MPI_TO_STR,
   /** Can not complete NULL char */
   NANO_ERR_CANT_COMPLETE_NULL_CHAR,
   /** Can not parse to MPI */
   NANO_ERR_CANT_PARSE_TO_MPI,
   /** Insuficient funds */
   NANO_ERR_INSUFICIENT_FUNDS,
   /** Error subtract MPI */
   NANO_ERR_SUB_MPI,
   /** Error add MPI */
   NANO_ERR_ADD_MPI,
   /** Does not make sense send negativative balance */
   NANO_ERR_NO_SENSE_VALUE_TO_SEND_NEGATIVE,
   /** Does not make sense send empty value */
   NANO_ERR_NO_SENSE_VALUE_TO_SEND_ZERO,
   /** Does not make sense negative balance */
   NANO_ERR_NO_SENSE_BALANCE_NEGATIVE,
   /** Invalid A mode value */
   NANO_ERR_VAL_A_INVALID_MODE,
   /** Can not parse temporary memory to uint_128_t */
   NANO_ERR_CANT_PARSE_TO_TEMP_UINT128_T,
   /** Invalid A mode value */
   NANO_ERR_VAL_B_INVALID_MODE,
   /** Can not parse raw A value to MPI */
   NANO_ERR_CANT_PARSE_RAW_A_TO_MPI,
   /** Can not parse raw B value to MPI */
   NANO_ERR_CANT_PARSE_RAW_B_TO_MPI,
   /** Unknown ADD/SUB mode */
   NANO_ERR_UNKNOWN_ADD_SUB_MODE,
   /** Invalid output result */
   NANO_ERR_INVALID_RES_OUTPUT
} f_nano_err;

#ifndef F_DOC_SKIP

 #define READ_SEED_FROM_STREAM (int)1
 #define READ_SEED_FROM_FILE (int)2
 #define WRITE_SEED_TO_STREAM (int)4
 #define WRITE_SEED_TO_FILE (int)8
 #define PARSE_JSON_READ_SEED_GENERIC (int)16
 #define F_STREAM_DATA_FILE_VERSION (uint32_t)((1<<16)|0)

#endif

/**
 * @typedef F_ENCRYPTED_BLOCK
 * @brief Block of encrypted file to store Nano SEED
 *
 * @struct f_nano_encrypted_wallet_t
 * @brief <b>struct</b> of the block of encrypted file to store Nano SEED
 */
typedef struct f_nano_encrypted_wallet_t {
   /** Salt of the sub block to be stored */
   uint8_t sub_salt[32];
   /** Initial sub vector */
   uint8_t iv[16];
   /** Reserved (not used) */
   uint8_t reserved[16];
   /** hash of Nano SEED when unencrypted */
   uint8_t hash_sk_unencrypted[32];
   /** Secret. SEED encrypted (second layer) */
   uint8_t sk_encrypted[32];
} __attribute__ ((packed)) F_ENCRYPTED_BLOCK;

#ifndef F_DOC_SKIP

 static const uint8_t NANO_WALLET_MAGIC[] = {'_', 'n', 'a', 'n', 'o', 'w', 'a', 'l', 'l', 'e', 't', 'f', 'i', 'l', 'e', '_'};
 #define F_NANO_FILE_DESC "NANO Seed Encrypted file/stream. Keep it safe and backup it. This file is protected by password. BUY BITCOIN and NANO !!!"
 #define F_DESC_SZ (size_t) (160-sizeof(uint32_t))

#endif

/**
 * @typedef F_NANO_CRYPTOWALLET
 * @brief Entire block of encrypted file to store Nano SEED
 *
 * @struct f_nano_crypto_wallet_t
 * @brief <b>struct</b> of the block of encrypted file to store Nano SEED
 */
typedef struct f_nano_crypto_wallet_t {
   /** Header of the file */
   uint8_t nano_hdr[sizeof(NANO_WALLET_MAGIC)];
   /** Version of the file */
   uint32_t ver;
   /** File description */
   uint8_t description[F_DESC_SZ];
   /** Salt of the first encryption layer */
   uint8_t salt[32];
   /** Initial vector of first encryption layer */
   uint8_t iv[16];
   /** Second encrypted block for Nano SEED */
   F_ENCRYPTED_BLOCK seed_block;
} __attribute__ ((packed)) F_NANO_CRYPTOWALLET;

#ifndef F_DOC_SKIP

_Static_assert((sizeof(F_NANO_CRYPTOWALLET)&0x1F)==0, "Error 1");
_Static_assert((sizeof(F_ENCRYPTED_BLOCK)&0x1F)==0, "Error 2");

#endif

/**
 * @def REP_XRB
 * @brief Representative XRB flag
 */
#define REP_XRB (uint8_t)0x4

/**
 * @def REP_XRB
 * @brief Sender XRB flag
 */
#define SENDER_XRB (uint8_t)0x02

/**
 * @def REP_XRB
 * @brief Destination XRB flag
 */
#define DEST_XRB (uint8_t)0x01

typedef enum f_write_seed_err_t {
   /** Error SUCCESS */
   WRITE_ERR_OK=0,
   /** Error NULL password */
   WRITE_ERR_NULL_PASSWORD=7180,
   /** Empty string */
   WRITE_ERR_EMPTY_STRING,
   /** Error MALLOC */
   WRITE_ERR_MALLOC,
   /** Error encrypt private key */
   WRITE_ERR_ENCRYPT_PRIV_KEY,
   /** Can not generate sub private key */
   WRITE_ERR_GEN_SUB_PRIV_KEY,
   /** Can not generate main private key */
   WRITE_ERR_GEN_MAIN_PRIV_KEY,
   /** Can not encrypt sub block */
   WRITE_ERR_ENCRYPT_SUB_BLOCK,
   /** Unknown option */
   WRITE_ERR_UNKNOWN_OPTION,
   /** File already exists */
   WRITE_ERR_FILE_ALREDY_EXISTS,
   /** Can not create file */
   WRITE_ERR_CREATING_FILE,
   /** Can not write file */
   WRITE_ERR_WRITING_FILE
} f_write_seed_err;

#ifndef F_DOC_SKIP

 #define F_RAW_TO_STR_UINT128 (int)1
 #define F_RAW_TO_STR_STRING (int)2
 #define F_RAW_STR_MAX_SZ (size_t)41 // 39 + '\0' + '.' -> 39 = log10(2^128)
 #define F_MAX_STR_RAW_BALANCE_MAX (size_t)40 //39+'\0'
 #define F_NANO_EMPTY_BALANCE "0.0"

#endif

/**
 * @typedef F_NANO_WALLET_INFO_BODY
 * @brief Store custom info body in a file to access SEED through a password
 *
 * @struct f_nano_wallet_info_bdy_t
 * @brief <b>struct</b> of the body block of the info file
 */
typedef struct f_nano_wallet_info_bdy_t {
   /** Wallet prefix: 0 for NANO; 1 for XRB */
   uint8_t wallet_prefix; // 0 for NANO; 1 for XRB
   /** Last used wallet number */
   uint32_t last_used_wallet_number;
   /** Wallet representative */
   char wallet_representative[MAX_STR_NANO_CHAR];
   /** Custom preferred max fee of Proof of Work */
   char max_fee[F_RAW_STR_MAX_SZ];
   /** Reserved */
   uint8_t reserved[44];
} __attribute__((packed)) F_NANO_WALLET_INFO_BODY;

#ifndef F_DOC_SKIP

 _Static_assert((sizeof(F_NANO_WALLET_INFO_BODY)&0x1F)==0, "Error F_NANO_WALLET_INFO_BODY is not byte aligned");

 #define F_NANO_WALLET_INFO_DESC "Nano file descriptor used for fast custom access. BUY BITCOIN AND NANO."
 #define F_NANO_WALLET_INFO_VERSION (uint16_t)((1<<8)|1)
 static const uint8_t F_NANO_WALLET_INFO_MAGIC[] = {'_', 'n', 'a', 'n', 'o', 'w', 'a', 'l', 'l', 'e', 't', '_', 'n', 'f', 'o', '_'};

 #define F_NANO_DESC_SZ (size_t)78

#endif

/**
 * @typedef F_NANO_WALLET_INFO
 * @brief Store custom info body in a file to access SEED through a password
 *
 * @struct f_nano_wallet_info_t
 * @brief <b>struct</b> of the body block of the info file
 */
typedef struct f_nano_wallet_info_t {
   /** Header magic */
   uint8_t header[sizeof(F_NANO_WALLET_INFO_MAGIC)];
   /** Version */
   uint16_t version;
   /** Description */
   char desc[F_NANO_DESC_SZ];
   /** Nano SEED hash file */
   uint8_t nanoseed_hash[32];
   /** File info integrity of the body block */
   uint8_t file_info_integrity[32];
   /** Body of the file info */
   F_NANO_WALLET_INFO_BODY body;
} __attribute__((packed)) F_NANO_WALLET_INFO;

#ifndef F_DOC_SKIP

 _Static_assert((sizeof(F_NANO_WALLET_INFO)&0x1F)==0, "Error F_NANO_WALLET_INFO is not byte aligned");

#endif

/**
 * @typedef F_FILE_INFO_ERR
 * @brief Typedef Error enumerator for info file functions
 *
 * @struct f_file_info_err_t
 * @brief Error enumerator for info file functions
 */
typedef enum f_file_info_err_t {
   /** SUCCESS */
   F_FILE_INFO_ERR_OK=0,
   /** Can't open info file */
   F_FILE_INFO_ERR_CANT_OPEN_INFO_FILE=7001,
   /** Encrypted file with Nano SEED not found */
   F_FILE_INFO_ERR_NANO_SEED_ENCRYPTED_FILE_NOT_FOUND,
   /** Can not delete Nano info file */
   F_FILE_INFO_ERR_CANT_DELETE_NANO_INFO_FILE,
   /** Fatal Error MALLOC */
   F_FILE_INFO_ERR_MALLOC,
   /** Can not read encrypted Nano SEED in file */
   F_FILE_INFO_ERR_CANT_READ_NANO_SEED_ENCRYPTED_FILE,
   /** Can not read info file */
   F_FILE_INFO_ERR_CANT_READ_INFO_FILE,
   /** Invalid info file header */
   F_FILE_INFO_INVALID_HEADER_FILE,
   /** Invalid SHA256 info file */
   F_FILE_INFO_ERR_INVALID_SHA256_INFO_FILE,
   /** Nano SEED hash failed */
   F_FILE_INFO_ERR_NANO_SEED_HASH_FAIL,
   /** Invalid representative */
   F_FILE_INFO_ERR_NANO_INVALID_REPRESENTATIVE,
   /** Invalid max fee value */
   F_FILE_INFO_ERR_NANO_INVALID_MAX_FEE_VALUE,
   /** Can not open info file for write */
   F_FILE_INFO_ERR_OPEN_FOR_WRITE_INFO,
   /** Error File Exists */
   F_FILE_INFO_ERR_EXISTING_FILE,
   /** Can not write info file */
   F_FILE_INFO_ERR_CANT_WRITE_FILE_INFO
} F_FILE_INFO_ERR;

#ifndef F_DOC_SKIP

 #define F_NANO_ADD_A_B (uint32_t)(1<<0)
 #define F_NANO_SUB_A_B (uint32_t)(1<<1)
 #define F_NANO_A_RAW_128 (uint32_t)(1<<2)
 #define F_NANO_A_RAW_STRING (uint32_t)(1<<3)
 #define F_NANO_A_REAL_STRING (uint32_t)(1<<4)
 #define F_NANO_B_RAW_128 (uint32_t)(1<<5)
 #define F_NANO_B_RAW_STRING (uint32_t)(1<<6)
 #define F_NANO_B_REAL_STRING (uint32_t)(1<<7)
 #define F_NANO_RES_RAW_128 (uint32_t)(1<<8)
 #define F_NANO_RES_RAW_STRING (uint32_t)(1<<9)
 #define F_NANO_RES_REAL_STRING (uint32_t)(1<<10)
 #define F_NANO_C_RAW_128 (uint32_t)(F_NANO_B_RAW_128<<16)
 #define F_NANO_C_RAW_STRING (uint32_t)(F_NANO_B_RAW_STRING<<16)
 #define F_NANO_C_REAL_STRING (uint32_t)(F_NANO_B_REAL_STRING<<16)

 #define F_NANO_COMPARE_EQ (uint32_t)(1<<16) //Equal
 #define F_NANO_COMPARE_LT (uint32_t)(1<<17) // Lesser than
 #define F_NANO_COMPARE_LEQ (F_NANO_COMPARE_LT|F_NANO_COMPARE_EQ) // Less or equal
 #define F_NANO_COMPARE_GT (uint32_t)(1<<18) // Greater
 #define F_NANO_COMPARE_GEQ (F_NANO_COMPARE_GT|F_NANO_COMPARE_EQ) // Greater or equal
 #define DEFAULT_MAX_FEE "0.001"

#endif

#ifndef F_ESP32
typedef enum f_nano_create_block_dyn_err_t {
   NANO_CREATE_BLK_DYN_OK = 0,
   NANO_CREATE_BLK_DYN_BLOCK_NULL = 8000,
   NANO_CREATE_BLK_DYN_ACCOUNT_NULL,
   NANO_CREATE_BLK_DYN_PREV_NULL,
   NANO_CREATE_BLK_DYN_REP_NULL,
   NANO_CREATE_BLK_DYN_BALANCE_NULL,
   NANO_CREATE_BLK_DYN_SEND_RECEIVE_NULL,
   NANO_CREATE_BLK_DYN_LINK_NULL,
   NANO_CREATE_BLK_DYN_BUF_MALLOC,
   NANO_CREATE_BLK_DYN_MALLOC,
   NANO_CREATE_BL_DYN_WRONG_PREVIOUS_SZ,
   NANO_CREATE_BL_DYN_WRONG_PREVIOUS_STR_SZ,
   NANO_CREATE_BL_DYN_PARSE_STR_HEX_ERR

} F_NANO_CREATE_BLOCK_DYN_ERR;

#endif

/**
 * @fn double to_multiplier(uint64_t difficulty, uint64_t base_difficulty)
 * @brief Calculates a relative difficulty compared PoW with another
 *
 * @param [in] dificulty Work difficulty
 * @param [in] base_difficulty Base difficulty
 * Details <a href="https://docs.nano.org/integration-guides/work-generation/#difficulty-multiplier">here</a>
 *
 * @see from_multiplier()
 * @retval Calculated value
 */
double to_multiplier(uint64_t, uint64_t);

/**
 * @fn uint64_t from_multiplier(double multiplier, uint64_t base_difficulty)
 * @brief Calculates a PoW given a multiplier and base difficulty
 *
 * @param [in] multiplier Multiplier of the work
 * @param [in] base_difficulty Base difficulty
 * Details <a href="https://docs.nano.org/integration-guides/work-generation/#difficulty-multiplier">here</a>
 *
 * @see to_multiplier()
 * @retval Calculated value
 */
uint64_t from_multiplier(double, uint64_t);

/**
 * @fn void f_set_dictionary_path(const char *path)
 * @brief Set default dictionary file and path to <b>myNanoEmbedded</b> library
 *
 * @param [in] path Path to dictionary file
 *
 * If f_set_dictionary_path() is not used in <b>myNanoEmbedded</b> library then default path stored in <i>BIP39_DICTIONARY</i> is used
 * @see f_get_dictionary_path()
 */
void f_set_dictionary_path(const char *);

/**
 * @fn char *f_get_dictionary_path(void);
 * @brief Get default dictionary path in <b>myNanoEmbedded</b> library
 *
 * @retval Path and name of the dictionary file
 * @see f_set_dictionary_path()
 */
char *f_get_dictionary_path(void);

/**
 * @fn int f_generate_token(F_TOKEN signature, void *data, size_t data_sz, const char *password)
 * @brief Generates a non deterministic token given a message data and a password
 *
 * @param [out] signature 128 bit non deterministic token
 * @param [in] data Data to be signed in token
 * @param [in] data_sz Size of data
 * @param [in] password Password
 *
 * @retval 0: On Success, otherwise Error
 * @see f_verify_token()
 */
int f_generate_token(F_TOKEN, void *, size_t, const char *);

/**
 * @fn int f_verify_token(F_TOKEN signature, void *data, size_t data_sz, const char *password)
 * @brief Verifies if a token is valid given data and password
 *
 * @param [in] signature 128 bit non deterministic token
 * @param [in] data Data to be signed in token
 * @param [in] data_sz Size of data
 * @param [in] password Password
 *
 * @retval 0: On if invalid; 1 if valid ; less than zero if an error occurs
 * @see f_generate_token()
 */
int f_verify_token(F_TOKEN, void *, size_t, const char *);

/**
 * @fn int f_cloud_crypto_wallet_nano_create_seed(size_t entropy, char *file_name, char *password)
 * @brief Generates a new SEED and saves it to an non deterministic encrypted file. <i>password</i> is mandatory
 *
 * @param [in] entropy Entropy type.
 *     Entropy type are:<br><br>
 *         F_ENTROPY_TYPE_PARANOIC<br>F_ENTROPY_TYPE_EXCELENT<br>F_ENTROPY_TYPE_GOOD<br>F_ENTROPY_TYPE_NOT_ENOUGH<br>
 *         F_ENTROPY_TYPE_NOT_RECOMENDED<br>
 *
 * @param [in] file_name The file and path to be stored in your file system directory. It can be <i>NULL</i>. If you parse a <i>NULL</i> value then file
 * will be stored in <i>NANO_ENCRYPTED_SEED_FILE</i> variable file system pointer.
 * @param [in] password Password of the encrypted file. It can NOT be <i>NULL</i> or EMPTY
 *
 * @brief <strong>WARNING</strong>
 *
 * @brief <i>f_cloud_crypto_wallet_nano_create_seed()</i> does not verify your password. It is recommended to use a strong password like symbols,
 * capital letters and numbers to keep your SEED safe and avoid brute force attacks.
 *
 * @brief You can use <i>f_pass_must_have_at_least()</i> function to check passwords strength
 * @retval 0: On Success, otherwise Error
 *
 */
int f_cloud_crypto_wallet_nano_create_seed(size_t, char *, char *);

/**
 * @fn int f_generate_nano_seed(NANO_SEED seed, uint32_t entropy)
 * @brief Generates a new SEED and stores it to <i>seed</i> pointer
 * @param [out] seed SEED generated in system PRNG or TRNG
 * @param [in] entropy Entropy type.
 *     Entropy type are:<br><br>
 *         F_ENTROPY_TYPE_PARANOIC<br>F_ENTROPY_TYPE_EXCELENT<br>F_ENTROPY_TYPE_GOOD<br>F_ENTROPY_TYPE_NOT_ENOUGH<br>
 *         F_ENTROPY_TYPE_NOT_RECOMENDED<br>
 *
 * @retval 0: On Success, otherwise Error
 *
 */
int f_generate_nano_seed(NANO_SEED, uint32_t);

/**
 * @fn int pk_to_wallet(char *out, char *prefix, NANO_PUBLIC_KEY_EXTENDED pubkey_extended)
 * @brief Parse a Nano public key to Base32 Nano wallet string
 * @param [out] out Output string containing the wallet
 * @param [in] prefix Nano prefix.<br> <br><i>NANO_PREFIX</i> for nano_<br><i>XRB_PREFIX</i> for xrb_<br>
 * @param [in, out] pubkey_extended Public key to be parsed to string
 *
 * WARNING:
 * <i>pubkey_extended</i> is destroyed when parsing to Nano base32 encoding
 *
 * @retval 0: On Success, otherwise Error
 * @see nano_base_32_2_hex()
 *
 */
int pk_to_wallet(char *, char *, NANO_PUBLIC_KEY_EXTENDED);

/**
 * @fn int f_seed_to_nano_wallet(NANO_PRIVATE_KEY private_key, NANO_PUBLIC_KEY public_key, NANO_SEED seed, uint32_t wallet_number)
 * @brief Extracts one key pair from Nano SEED given a wallet number
 * @param [out] private_key Private key of the <i>wallet_number</i> from given <i>seed</i>
 * @param [out] public_key Public key of the <i>wallet_number</i> from given <i>seed</i>
 * @param [in, out] seed Nano SEED
 * @param [in] wallet_number Wallet number of key pair to be extracted from Nano SEED
 *
 * WARNING 1:
 * - Seed must be read from memory
 * - Seed is destroyed when extracting public and private keys
 *
 * WARNING 2:
 * - Never expose SEED and private key. This function destroys seed and any data after execution and finally parse public and private keys to output.
 *
 * @retval 0: On Success, otherwise Error
 */
int f_seed_to_nano_wallet(NANO_PRIVATE_KEY, NANO_PUBLIC_KEY, NANO_SEED, uint32_t);

/**
 *
 * @fn int f_nano_is_valid_block(F_BLOCK_TRANSFER *block)
 * @brief Checks if Binary Nano Block is valid
 * @param [in] block Nano Block
 *
 * @return 0 if is invalid block or 1 if is valid block
 *
 */
int f_nano_is_valid_block(F_BLOCK_TRANSFER *);

/**
 * @fn int f_nano_block_to_json(char *dest, size_t *olen, size_t dest_size, F_BLOCK_TRANSFER *user_block)
 * @brief Parse a Nano Block to JSON
 *
 * @param [out] dest Destination of the converted JSON block
 * @param [out] olen Output length of the converted JSON block. <i>olen</i> can be NULL. If NULL, destination size contains a NULL char
 * @param [in] dest_size Size of <i>dest<i> memory buffer
 * @param [in] user_block User Nano block
 *
 * @return 0 if success, non zero if error
 *
 */
int f_nano_block_to_json(char *, size_t *, size_t, F_BLOCK_TRANSFER *);

/**
 * @fn int f_nano_get_block_hash(uint8_t *hash, F_BLOCK_TRANSFER *block)
 * @brief Gets a hash from Nano block
 *
 * @param [out] hash Output hash
 * @param [in] block Nano Block
 *
 * @return 0 if success, non zero if error
 *
 */
int f_nano_get_block_hash(uint8_t *, F_BLOCK_TRANSFER *);

/**
 * @fn int f_nano_get_p2pow_block_hash(uint8_t *user_hash, uint8_t *fee_hash, F_BLOCK_TRANSFER *block)
 * @brief Get Nano user block hash and Nano fee block hashes from P2PoW block
 *
 * @param [out] user_hash Hash of the user block
 * @param [out] fee_hash Hash of the P2PoW block
 * @param [in] block Input Nano Block
 *
 * @return 0 if success, non zero if error
 *
 */
int f_nano_get_p2pow_block_hash(uint8_t *, uint8_t *, F_BLOCK_TRANSFER *);

/**
 * @fn int f_nano_p2pow_to_JSON(char *buffer, size_t *olen, size_t buffer_sz, F_BLOCK_TRANSFER *block)
 * @brief Parse binary P2PoW block to JSON
 *
 * @param [out] buffer Output JSON string
 * @param [out] olen Output JSON string size. <i>olen</i> can be NULL. If NULL, <i>buffer</i> will be terminated with a NULL char
 * @param [in] buffer_sz Size of memory buffer
 * @param [in] block P2PoW block
 *
 * @return 0 if success, non zero if error
 *
 */
int f_nano_p2pow_to_JSON(char *, size_t *, size_t, F_BLOCK_TRANSFER *);

/**
 * @fn char *f_nano_key_to_str(char *out, unsigned char *key)
 * @brief Parse a raw binary public key to string
 * @param [out] out Pointer to outuput string
 * @param [in] in Pointer to raw public key
 *
 * @return A pointer to output string
 *
 */
char *f_nano_key_to_str(char *, unsigned char *);

/**
 * @fn int f_nano_seed_to_bip39(char *buf, size_t buf_sz, size_t *out_buf_len, NANO_SEED seed, char *dictionary_file)
 * @brief Parse Nano SEED to Bip39 encoding given a dictionary file
 * @param [out] buf Output string containing encoded Bip39 SEED
 * @param [in] buf_sz Size of memory of buf pointer
 * @param [out] out_buf_len If <i>out_buf_len</i> is NOT NULL then <i>out_buf_len</i> returns the size of string encoded Bip39 and <i>out</i> with non NULL char.
 * If <i>out_buf_len</i> is NULL then <i>out</i> has a string encoded Bip39 with a NULL char.
 * @param [in] seed Nano SEED
 * @param [in] dictionary_file Path to dictionary file
 *
 * WARNING
 * Sensive data. Do not share any SEED or Bip39 encoded string ! 
 *
 * @retval 0: On Success, otherwise Error
 *
 * @see f_bip39_to_nano_seed()
 * 
 */
int f_nano_seed_to_bip39(char *, size_t, size_t *, NANO_SEED, char *);

/**
 * @fn int f_bip39_to_nano_seed(uint8_t *seed, char *str, char *dictionary)
 * @brief Parse Nano Bip39 encoded string to raw Nano SEED given a dictionary file
 * @param [out] seed Nano SEED
 * @param [in] str A encoded Bip39 string pointer
 * @param [in] dictionary A string pointer path to file
 *
 * WARNING
 * Sensive data. Do not share any SEED or Bip39 encoded string !
 *
 * @retval 0: On Success, otherwise Error
 *
 * @see f_nano_seed_to_bip39()
 */
int f_bip39_to_nano_seed(uint8_t *, char *, char *);

/**
 * @fn int f_parse_nano_seed_and_bip39_to_JSON(char *dest, size_t dest_sz, size_t *olen, void *source_data, int source, const char *password)
 * @brief Parse Nano SEED and Bip39 to JSON given a encrypted data in memory or encrypted data in file or unencrypted seed in memory
 * @param [out] dest Destination JSON string pointer
 * @param [in] dest_sz Buffer size of <i>dest</i> pointer
 * @param [out] olen Size of the output JSON string. If NULL string JSON returns a NULL char at the end of string otherwise it will return the size of the string
 * is stored into <i>olen</i> variable
 * without NULL string in <i>dest</i>
 * @param [in] source_data Input data source (encrypted file | encrypted data in memory | unencrypted seed in memory)
 * @param [in] source Source data type: <br>
 *     - PARSE_JSON_READ_SEED_GENERIC: If seed are in memory pointed in <i>source_data</i>. Password is ignored. Can be NULL.
 *     - READ_SEED_FROM_STREAM: Read encrypted data from stream pointed in <i>source_data</i>. Password is required.
 *     - READ_SEED_FROM_FILE: Read encrypted data stored in a file where <i>source_data</i> is path to file. Password is required.
 * @param [in] password Required for READ_SEED_FROM_STREAM and READ_SEED_FROM_FILE sources
 *
 * WARNING
 * Sensive data. Do not share any SEED or Bip39 encoded string !
 *
 * @retval 0: On Success, otherwise Error
 * @see f_read_seed()
 */
int f_parse_nano_seed_and_bip39_to_JSON(char *, size_t, size_t *, void *, int, const char *);

/**
 * @fn int f_read_seed(uint8_t *seed, const char *passwd, void *source_data, int force_read, int source)
 * @brief Extracts a Nano SEED from encrypted stream in memory or in a file
 * @param [out] seed Output Nano SEED
 * @param [in] passwd Password (always required)
 * @param [in] source_data Encrypted source data from memory or path pointed in <i>source_data</i>
 * @param [in] force_read If non zero value then forces reading from a corrupted file. This param is ignored when reading <i>source_data</i> from memory
 * @param [in] source Source data type: <br>
 *     - READ_SEED_FROM_STREAM: Read encrypted data from stream pointed in <i>source_data</i>. Password is required.
 *     - READ_SEED_FROM_FILE: Read encrypted data stored in a file where <i>source_data</i> is path to file. Password is required.
 *
 * WARNING
 * Sensive data. Do not share any SEED !
 *
 * @retval 0: On Success, otherwise Error
 * @see f_parse_nano_seed_and_bip39_to_JSON() f_write_seed()
 */
int f_read_seed(uint8_t *, const char *, void *, int, int);

/**
 * @fn int f_nano_raw_to_string(char *str, size_t *olen, size_t str_sz, void *raw, int raw_type)
 * @brief Converts Nano raw balance [string | f_uint128_t] to real string value
 * @param [out] str Output real string value
 * @param [out] olen Size of output real string value. It can be NULL. If NULL output <i>str</i> will have a NULL char at the end.
 * @param [in] str_sz Size of <i>str</i> buffer
 * @param [in] raw Raw balance.
 * @param [in] raw_type Raw balance type:
 *     - F_RAW_TO_STR_UINT128 for raw <b>f_uint128_t</b> balance
 *     - F_RAW_TO_STR_STRING for raw <b>char</b> balance
 *
 * @retval 0: On Success, otherwise Error
 * @see f_nano_valid_nano_str_value()
 */
int f_nano_raw_to_string(char *, size_t *, size_t, void *, int);

/**
 * @fn int f_nano_valid_nano_str_value(const char *str)
 * @brief Check if a real string or raw string are valid Nano balance
 * @param [in] str Value to be checked
 *
 * @retval 0: If valid, otherwise is invalid
 * @see f_nano_raw_to_string()
 */
int f_nano_valid_nano_str_value(const char *);

/**
 * @fn int valid_nano_wallet(const char *wallet)
 * @brief Check if a string containing a Base32 Nano wallet is valid
 * @param [in] wallet Base32 Nano wallet encoded string
 *
 * @retval 0: If valid wallet otherwise is invalid
 */
int valid_nano_wallet(const char *);

/**
 * @fn int nano_base_32_2_hex(uint8_t *res, char *str_wallet)
 * @brief Parse Nano Base32 wallet string to public key binary
 * @param [out] res Output raw binary public key
 * @param [in] str_wallet Valid Base32 encoded Nano string to be parsed
 *
 * @retval 0: On Success, otherwise Error
 * @see pk_to_wallet()
 */
int nano_base_32_2_hex(uint8_t *, char *);

/**
 * @fn int f_nano_transaction_to_JSON(char *str, size_t str_len, size_t *str_out, NANO_PRIVATE_KEY_EXTENDED private_key, F_BLOCK_TRANSFER *block_transfer)
 * @brief Sign a block pointed in <i>block_transfer</i> with a given <i>private_key</i> and stores signed block to <i>block_transfer</i> and parse to JSON Nano RPC
 * @param [out] str A string pointer to store JSON Nano RPC
 * @param [in] str_len Size of buffer in <i>str</i> pointer
 * @param [out] str_out Size of JSON string. <i>str_out</i> can be NULL
 * @param [in] private_key Private key to sign the block <i>block_transfer</i>
 * @param [in, out] block_transfer Nano block containing raw data to be stored in Nano Blockchain
 *
 * WARNING
 * Sensive data. Do not share any PRIVATE KEY
 *
 * @retval 0: On Success, otherwise Error
 */
int f_nano_transaction_to_JSON(char *, size_t, size_t *, NANO_PRIVATE_KEY_EXTENDED, F_BLOCK_TRANSFER *);

/**
 * @fn int valid_raw_balance(const char *balance)
 * @brief Checks if a string buffer pointed in <i>balance</i> is a valid raw balance
 * @param [in] balance Pointer containing a string buffer
 *
 * @retval 0: On Success, otherwise Error
 */
int valid_raw_balance(const char *);

/**
 * @fn int is_null_hash(uint8_t *hash)
 * @brief Check if 32 bytes hash is filled with zeroes
 * @param [in] hash 32 bytes binary <i>hash</i>
 *
 * @retval 1: If zero filled buffer, otherwise 0
 */
int is_null_hash(uint8_t *);

/**
 * @fn int is_nano_prefix(const char *nano_wallet, const char *prefix)
 * @brief Checks <i>prefix</i> in <i>nano_wallet</i>
 * @param [in] nano_wallet Base32 Nano wallet encoded string
 * @param [in] prefix Prefix type
 *     - NANO_PREFIX for nano_
 *     - XRB_PREFIX for xrb_
 *
 * @retval 1: If <i>prefix</i> in <i>nano_wallet</i>, otherwise 0
 *
 */
int is_nano_prefix(const char *, const char *);

/**
 * @fn F_FILE_INFO_ERR f_get_nano_file_info(F_NANO_WALLET_INFO *info)
 * @brief Opens default file <i>walletsinfo.i</i> (if exists) containing information <i>F_NANO_WALLET_INFO</i> structure and parsing to pointer <i>info</i> if success
 * @param [out] info Pointer to buffer to be parsed struct from <i>$PATH/walletsinfo.i</i> file.
 *
 * @retval F_FILE_INFO_ERR_OK: If Success, otherwise <i>F_FILE_INFO_ERR</i> enum type error
 * @see F_FILE_INFO_ERR enum type error for detailed error and f_nano_wallet_info_t for info type details
 */
F_FILE_INFO_ERR f_get_nano_file_info(F_NANO_WALLET_INFO *);

/**
 * @fn F_FILE_INFO_ERR f_set_nano_file_info(F_NANO_WALLET_INFO *info, int overwrite_existing_file)
 * @brief Saves wallet information stored at buffer struct <i>info</i> to file <i>walletsinfo.i</i>
 * @param [in] info Pointer to data to be saved at <i>$PATH/walletsinfo.i</i> file.
 * @param [in] overwrite_existing_file If non zero then overwrites file <i>$PATH/walletsinfo.i</i>
 *
 * @retval F_FILE_INFO_ERR_OK: If Success, otherwise <i>F_FILE_INFO_ERR</i> enum type error
 * @see F_FILE_INFO_ERR enum type error for detailed error and f_nano_wallet_info_t for info type details
 */
F_FILE_INFO_ERR f_set_nano_file_info(F_NANO_WALLET_INFO *, int);

/**
 * @fn f_nano_err f_nano_value_compare_value(void *valA, void *valB, uint32_t *mode_compare)
 * @brief Comparare two Nano balance
 * @param [in] valA Nano balance value A
 * @param [in] valB Nano balance value B
 * @param [in,out] mode_compare Input mode and output result
 *     <br/><br/>Input mode:
 *     - <i>F_NANO_A_RAW_128</i> if <i>valA</i> is big number raw buffer type
 *     - <i>F_NANO_A_RAW_STRING</i> if <i>valA</i> is big number raw string type
 *     - <i>F_NANO_A_REAL_STRING</i> if <i>valA</i> is real number string type
 *     - <i>F_NANO_B_RAW_128</i> if <i>valB</i> is big number raw buffer type
 *     - <i>F_NANO_B_RAW_STRING</i> if <i>valB</i> is big number raw string type
 *     - <i>F_NANO_B_REAL_STRING</i> if <i>valB</i> is real number string type
 *     <br/><br/>Output type:
 *     - <i>F_NANO_COMPARE_EQ</i> If <i>valA</i> is greater than <i>valB</i>
 *     - <i>F_NANO_COMPARE_LT</i> if <i>valA</i> is lesser than <i>valB</i>
 *     - <i>F_NANO_COMPARE_GT</i> if <i>valA</i> is greater than <i>valB</i>
 *
 * @retval NANO_ERR_OK: If Success, otherwise f_nano_err_t enum type error
 * @see f_nano_err_t for f_nano_err enum error type
 */
f_nano_err f_nano_value_compare_value(void *, void *, uint32_t *);

/**
 * @fn f_nano_err f_nano_verify_nano_funds(void *balance, void *value_to_send, void *fee, uint32_t mode)
 * @brief Check if Nano balance has sufficient funds
 * @param [in] balance Nano balance
 * @param [in] value_to_send Value to send
 * @param [in] fee Fee value (it can be NULL)
 * @param [in] mode Value type mode
 *     - <i>F_NANO_A_RAW_128</i> if <i>balance</i> is big number raw buffer type
 *     - <i>F_NANO_A_RAW_STRING</i> if <i>balance</i> is big number raw string type
 *     - <i>F_NANO_A_REAL_STRING</i> if <i>balance</i> is real number string type
 *     - <i>F_NANO_B_RAW_128</i> if <i>value_to_send</i> is big number raw buffer type
 *     - <i>F_NANO_B_RAW_STRING</i> if <i>value_to_send</i> is big number raw string type
 *     - <i>F_NANO_B_REAL_STRING</i> if <i>value_to_send</i> is real number string type
 *     - <i>F_NANO_C_RAW_128</i> if <i>fee</i> is big number raw buffer type (can be ommited if <i>fee</i> is NULL)
 *     - <i>F_NANO_C_RAW_STRING</i> if <i>fee</i> is big number raw string type (can be ommited if <i>fee</i> is NULL)
 *     - <i>F_NANO_C_REAL_STRING</i> if <i>fee</i> is real number string type (can be ommited if <i>fee</i> is NULL)
 *
 * @retval NANO_ERR_OK: If Success, otherwise f_nano_err_t enum type error
 * @see f_nano_err_t for f_nano_err enum error type
 */
f_nano_err f_nano_verify_nano_funds(void *, void *, void *, uint32_t);

/**
 * @fn f_nano_err f_nano_parse_raw_str_to_raw128_t(uint8_t *res, const char *raw_str_value)
 * @brief Parse a raw string balance to raw big number 128 bit
 * @param [out] res Binary raw balance
 * @param [in] raw_str_value Raw balance string
 *
 * @retval NANO_ERR_OK: If Success, otherwise f_nano_err_t enum type error
 * @see f_nano_err_t for f_nano_err enum error type
 */
f_nano_err f_nano_parse_raw_str_to_raw128_t(uint8_t *, const char *);

/**
 * @fn f_nano_err f_nano_parse_real_str_to_raw128_t(uint8_t *res, const char *real_str_value)
 * @brief Parse a real string balance to raw big number 128 bit
 * @param [out] res Binary raw balance
 * @param [in] real_str_value Real balance string
 *
 * @retval NANO_ERR_OK: If Success, otherwise f_nano_err_t enum type error
 * @see f_nano_err_t for f_nano_err enum error type
 */
f_nano_err f_nano_parse_real_str_to_raw128_t(uint8_t *, const char *);

/**
 * @fn f_nano_err f_nano_add_sub(void *res, void *valA, void *valB, uint32_t mode)
 * @brief Add/Subtract two Nano balance values and stores value in <i>res</i>
 * @param [out] res Result value res = valA + valB or res = valA - valB
 * @param [in] valA Input balance A value
 * @param [in] valB Input balance B value
 * @param [in] mode Mode type:
 *     - <i>F_NANO_ADD_A_B</i> valA + valB
 *     - <i>F_NANO_SUB_A_B</i> valA - valB
 *     - <i>F_NANO_RES_RAW_128</i> Output is a raw data 128 bit big number result
 *     - <i>F_NANO_RES_RAW_STRING</i> Output is a 128 bit Big Integer string
 *     - <i>F_NANO_RES_REAL_STRING</i> Output is a Real string value
 *     - <i>F_NANO_A_RAW_128</i> if <i>balance</i> is big number raw buffer type
 *     - <i>F_NANO_A_RAW_STRING</i> if <i>balance</i> is big number raw string type
 *     - <i>F_NANO_A_REAL_STRING</i> if <i>balance</i> is real number string type
 *     - <i>F_NANO_B_RAW_128</i> if <i>value_to_send</i> is big number raw buffer type
 *     - <i>F_NANO_B_RAW_STRING</i> if <i>value_to_send</i> is big number raw string type
 *     - <i>F_NANO_B_REAL_STRING</i> if <i>value_to_send</i> is real number string type
 *
 * @retval NANO_ERR_OK: If Success, otherwise f_nano_err_t enum type error
 * @see f_nano_err_t for f_nano_err enum error type
 */
f_nano_err f_nano_add_sub(void *, void *, void *, uint32_t);

/**
 * @fn int f_nano_sign_block(F_BLOCK_TRANSFER *user_block, F_BLOCK_TRANSFER *fee_block, NANO_PRIVATE_KEY_EXTENDED private_key)
 * @brief Signs <i>user_block</i> and worker <i>fee_block</i> given a private key <i>private_key</i>
 * @param [in, out] user_block User block to be signed with a private key <i>private_key</i>
 * @param [in, out] fee_block Fee block to be signed with a private key <i>private_key</i>. Can be NULL if worker does not require fee
 * @param [in] private_key Private key to sign block(s)
 *
 * @retval 0: If Success, otherwise error
 * @see f_nano_transaction_to_JSON()
 */
int f_nano_sign_block(F_BLOCK_TRANSFER *, F_BLOCK_TRANSFER *, NANO_PRIVATE_KEY_EXTENDED);

/**
 * @fn f_write_seed_err f_write_seed(void *source_data, int source, uint8_t *seed, char *passwd)
 * @brief Writes a SEED into a ecrypted with password with non deterministic stream in memory or file
 * @param [out] source_data Memory pointer or file name
 * @param [in] source Source of output data:
 *     - <i>WRITE_SEED_TO_STREAM</i> Output data is a pointer to memory to store encrypted Nano SEED data
 *     - <i>WRITE_SEED_TO_FILE</i> Output is a string filename to store encrypted Nano SEED data
 * @param [in] seed Nano SEED to be stored in encrypted stream or file
 * @param [in] passwd (Mandatory) It can not be null string or NULL. See <i>f_pass_must_have_at_least()</i> function to check passwords strength
 *
 * @retval 0: If Success, otherwise error
 * @see f_read_seed()
 */
f_write_seed_err f_write_seed(void *, int, uint8_t *, char *);

/**
 * @fn f_nano_err f_nano_balance_to_str(char *str, size_t str_len, size_t *out_len, f_uint128_t value)
 * @brief Converts a raw Nano balance to string raw balance
 * @param [out] str Output string pointer
 * @param [in] str_len Size of string pointer memory
 * @param [out] out_len Output length of converted value to string. If <i>out_len</i> is NULL then <i>str</i> returns converted value with NULL terminated string
 * @param [in] value Raw Nano balance value
 *
 * @retval 0: If success, otherwise error.
 * @see function f_nano_parse_raw_str_to_raw128_t() and return errors f_nano_err
 *
 */
f_nano_err f_nano_balance_to_str(char *, size_t, size_t *, f_uint128_t);


/**
 * @def F_BRAIN_WALLET_VERY_POOR
 * @brief [very poor]. Crack within seconds or less
 */
#define F_BRAIN_WALLET_VERY_POOR (uint32_t)0

/**
 * @def F_BRAIN_WALLET_POOR
 * @brief [poor]. Crack within minutes
 */
#define F_BRAIN_WALLET_POOR (uint32_t)1

/**
 * @def F_BRAIN_WALLET_VERY_BAD
 * @brief [very bad]. Crack within one hour
 */
#define F_BRAIN_WALLET_VERY_BAD (uint32_t)2

/**
 * @def F_BRAIN_WALLET_BAD
 * @brief [bad]. Crack within one day
 */
#define F_BRAIN_WALLET_BAD (uint32_t)3

/**
 * @def F_BRAIN_WALLET_VERY_WEAK
 * @brief [very weak]. Crack within one week
 */
#define F_BRAIN_WALLET_VERY_WEAK (uint32_t)4

/**
 * @def F_BRAIN_WALLET_WEAK
 * @brief [weak]. Crack within one month
 */
#define F_BRAIN_WALLET_WEAK (uint32_t)5

/**
 * @def F_BRAIN_WALLET_STILL_WEAK
 * @brief [still weak]. Crack within one year
 */
#define F_BRAIN_WALLET_STILL_WEAK (uint32_t)6

/**
 * @def F_BRAIN_WALLET_MAYBE_GOOD
 * @brief [maybe good for you]. Crack within one century
 */
#define F_BRAIN_WALLET_MAYBE_GOOD (uint32_t)7


/**
 * @def F_BRAIN_WALLET_GOOD
 * @brief [good]. Crack within one thousand year
 */
#define F_BRAIN_WALLET_GOOD (uint32_t)8

/**
 * @def F_BRAIN_WALLET_VERY_GOOD
 * @brief [very good]. Crack within ten thousand year
 */
#define F_BRAIN_WALLET_VERY_GOOD (uint32_t)9

/**
 * @def F_BRAIN_WALLET_NICE
 * @brief [very nice]. Crack withing one hundred thousand year
 */
#define F_BRAIN_WALLET_NICE (uint32_t)10

/**
 * @def F_BRAIN_WALLET_PERFECT
 * @brief [Perfect!] 3.34x10^53 Years to crack
 */
#define F_BRAIN_WALLET_PERFECT (uint32_t)11

/**
 * @fn int f_extract_seed_from_brainwallet(uint8_t *seed, char **warning_msg, uint32_t allow_mode, const char *brainwallet, const char *salt)
 * @brief Analyzes a text given a <i>mode</i> and if pass then the text in <i>braiwallet</i> is translated to a Nano SEED
 * @param [out] seed Output Nano SEED extracted from <i>brainwallet</i>
 * @param [out] warning_msg Warning message parsed to application. It can be NULL
 * @param [in] allow_mode Allow <i>mode</i>. Funtion will return SUCCESS only if permitted mode set by user
 *     <br/><br/>Allow mode are:
 *     - <i>F_BRAIN_WALLET_VERY_POOR</i> Crack within seconds or less
 *     - <i>F_BRAIN_WALLET_POOR</i> Crack within minutes
 *     - <i>F_BRAIN_WALLET_VERY_BAD</i> Crack within one hour
 *     - <i>F_BRAIN_WALLET_BAD</i> Crack within one day
 *     - <i>F_BRAIN_WALLET_VERY_WEAK</i> Crack within one week
 *     - <i>F_BRAIN_WALLET_WEAK</i> Crack within one month
 *     - <i>F_BRAIN_WALLET_STILL_WEAK</i> Crack within one year
 *     - <i>F_BRAIN_WALLET_MAYBE_GOOD</i> Crack within one century
 *     - <i>F_BRAIN_WALLET_GOOD</i> Crack within one thousand year
 *     - <i>F_BRAIN_WALLET_VERY_GOOD</i> Crack within ten thousand year
 *     - <i>F_BRAIN_WALLET_NICE</i> Crack withing one hundred thousand year
 *     - <i>F_BRAIN_WALLET_PERFECT</i> 3.34x10^53 Years to crack
 * @param [in] brainwallet Brainwallet text to be parsed. It can be NOT NULL or null string
 * @param [in] salt Salt of the Braiwallet. It can be NOT NULL or null string
 *
 * @retval 0: If success, otherwise error.
 * @see f_bip39_to_nano_seed()
 *
 */
int f_extract_seed_from_brainwallet(uint8_t *, char **, uint32_t, const char *, const char *);

/**
 * @fn int f_verify_work(uint64_t *result, const unsigned char *hash, uint64_t *work, uint64_t threshold)
 * @brief Verifies if Proof of Work of a given <i>hash</i> is valid
 * @param [out] result Result of work. It can be NULL
 * @param [in] hash Input <i>hash</i> for verification
 * @param [in] work Work previously calculated to be checked
 * @param [in] threshold Input <i>threshold</i>
 *
 * @retval 0: If is not valid or less than zero if error or greater than zero if is valid
 * @see f_nano_pow()
 */
int f_verify_work(uint64_t *, const unsigned char *, uint64_t *, uint64_t);

/**
 * @def F_SIGNATURE_RAW
 * @brief Signature is raw data
 * @see f_sign_data()
 */
#define F_SIGNATURE_RAW (uint32_t)1

/**
 * @def F_SIGNATURE_STRING
 * @brief Signature is hex ASCII encoded string
 * @see f_sign_data()
 */
#define F_SIGNATURE_STRING (uint32_t)2

/**
 * @def F_SIGNATURE_OUTPUT_RAW_PK
 * @brief Public key is raw data
 * @see f_sign_data()
 */
#define F_SIGNATURE_OUTPUT_RAW_PK (uint32_t)4

/**
 * @def F_SIGNATURE_OUTPUT_STRING_PK
 * @brief Public key is hex ASCII encoded string
 * @see f_sign_data()
 */
#define F_SIGNATURE_OUTPUT_STRING_PK (uint32_t)8

/**
 * @def F_SIGNATURE_OUTPUT_XRB_PK
 * @brief Public key is a XRB wallet encoded base32 string
 * @see f_sign_data()
 */
#define F_SIGNATURE_OUTPUT_XRB_PK (uint32_t)16

/**
 * @def F_SIGNATURE_OUTPUT_NANO_PK
 * @brief Public key is a NANO wallet encoded base32 string
 * @see f_sign_data()
 */
#define F_SIGNATURE_OUTPUT_NANO_PK (uint32_t)32

/**
 * @def F_IS_SIGNATURE_RAW_HEX_STRING
 * @brief Signature is raw hex string flag
 * @see f_sign_data()
 */
#define F_IS_SIGNATURE_RAW_HEX_STRING (uint32_t)64

/**
 * @def F_MESSAGE_IS_HASH_STRING
 * @brief Message is raw hex hash string
 * @see f_sign_data()
 */
#define F_MESSAGE_IS_HASH_STRING (uint32_t)128

/**
 * @def F_DEFAULT_THRESHOLD
 * @brief Default Nano Proof of Work Threshold
 */
#define F_DEFAULT_THRESHOLD (uint64_t) 0xffffffc000000000

/**
 * @fn int f_sign_data(unsigned char *signature, void *out_public_key, uint32_t ouput_type, const unsigned char *message, size_t msg_len, const unsigned char *private_key)
 * @brief Signs a <i>message</i> with a deterministic signature given a <i>private key</i>
 * @param [out] signature Output signature
 * @param [out] out_public_key Output public key. It can be NULL
 * @param [in] output_type Output type of public key. Public key types are:
 *     <br/><br/>
 *     - <i>F_SIGNATURE_RAW</i> Signature is raw 64 bytes long
 *     - <i>F_SIGNATURE_STRING</i> Singnature is hex ASCII encoded string
 *     - <i>F_SIGNATURE_OUTPUT_RAW_PK</i> Public key is raw 32 bytes data
 *     - <i>F_SIGNATURE_OUTPUT_STRING_PK</i> Public key is hes ASCII encoded string
 *     - <i>F_SIGNATURE_OUTPUT_XRB_PK</i> Public key is a XRB wallet encoded base32 string
 *     - <i>F_SIGNATURE_OUTPUT_NANO_PK</i> Public key is a NANO wallet encoded base32 string
 *
 *
 * @param [in] message Message to be signed with Elliptic Curve Ed25519 with blake2b hash
 * @param [in] msg_len Size of message to be signed
 * @param [in] private_key Private key to sign message
 *
 * @retval 0: If success, otherwise error.
 * @see f_verify_signed_data()
 *
 */
int f_sign_data(
   unsigned char *signature, 
   void *out_public_key, 
   uint32_t ouput_type, 
   const unsigned char *message,
   size_t msg_len, 
   const unsigned char *private_key);

/**
 * @def F_VERIFY_SIG_NANO_WALLET
 * @brief Public key is a NANO wallet with <i>XRB</i> or <i>NANO</i> prefixes encoded base32 string
 * @see f_verify_signed_data()
 */
#define F_VERIFY_SIG_NANO_WALLET (uint32_t)1

/**
 * @def F_VERIFY_SIG_RAW_HEX
 * @brief Public key raw 32 bytes data
 * @see f_verify_signed_data()
 */
#define F_VERIFY_SIG_RAW_HEX (uint32_t)2

/**
 * @def F_VERIFY_SIG_ASCII_HEX
 * @brief Public key is a hex ASCII encoded string
 * @see f_verify_signed_data()
 */
#define F_VERIFY_SIG_ASCII_HEX (uint32_t)4

/**
 * @fn int f_verify_signed_data(const unsigned char *signature, const unsigned char *message, size_t message_len, const void *public_key, uint32_t pk_type)
 * @brief Verifies if a signed message is valid
 * @param [in] signature Signature of the <i>message</i>
 * @param [in] message Message to be verified
 * @param [in] message_len Length of the message
 * @param [in] public_key Public key to verify signed message
 * @param [in] pk_type Type of the public key. Types are:
 *     <br/><br/>
 *     - <i>F_VERIFY_SIG_NANO_WALLET</i> Public key is a NANO wallet with <i>XRB</i> or <i>NANO</i> prefixes encoded base32 string
 *     - <i>F_VERIFY_SIG_RAW_HEX</i> Public key is raw 32 bytes data
 *     - <i>F_VERIFY_SIG_ASCII_HEX</i> Public key is a hex ASCII encoded string
 *
 * <b>Return value are</b>
 * - Greater than zero if <i>signature</i> is VALID
 * - 0 (zero) if <i>signature</i> is INVALID
 * - Negative if ERROR occurred
 *
 * @see f_sign_data()
 */
int f_verify_signed_data( const unsigned char *, const unsigned char *, size_t, const void *, uint32_t);

/**
 * @fn int f_is_valid_nano_seed_encrypted(void *stream, size_t stream_len, int read_from)
 * @brief Verifies if ecrypted Nano SEED is valid
 * @param [in] stream Encrypted binary data block coming from memory or file
 * @param [in] stream_len size of <i>stream</i> data
 * @param [in] read_from Source <i>READ_SEED_FROM_STREAM</i> if encrypted binary data is in memory or <i>READ_SEED_FROM_FILE</i> is in a file.
 *
 * @retval 0: If invalid, greater than zero if is valid or error if less than zero.
 */
int f_is_valid_nano_seed_encrypted(void *, size_t, int);

#ifndef F_ESP32

int nano_create_block_dynamic(
   F_BLOCK_TRANSFER **,
   const void *,
   size_t,
   const void *,
   size_t,
   const void *,
   size_t,
   const void *,
   const void *,
   uint32_t,
   const void *,
   int
);

/**
 * @fn int f_nano_pow(uint64_t *PoW_res, unsigned char *hash, const uint64_t threshold, int n_thr)
 * @brief Calculates a Proof of Work given a <i>hash</i>, <i>threshold</i> and number of threads <i>n_thr</i>
 * @param [out] PoW_res Output Proof of Work
 * @param [in] hash Input <i>hash</i>
 * @param [in] threshold Input <i>threshold</i>
 * @param [in] n_thr Number of threads. Default maximum value: 10. You can modify <i>F_NANO_POW_MAX_THREAD</i> in f_nano_crypto_util.h
 *
 * Mandatory: You need to enable attach a random function to your project using f_random_attach()
 * @retval 0: If success, otherwise error.
 * @see f_verify_work()
 */
int f_nano_pow(uint64_t *, unsigned char *, const uint64_t, int);
#endif

#ifdef __cplusplus
}
#endif

