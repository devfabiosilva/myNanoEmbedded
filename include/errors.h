//mon apr 26 20:56:00 -03 2021 

/**
 * @def ERROR_SUCCESS
 * @brief Error success. Most of the _myNanoEmbedded_ functions returns **ERROR_SUCCESS** when execution success.
 */
#define ERROR_SUCCESS 0

/**
 * @def ERROR_GEN_TOKEN_NO_RAND_NUM_GEN
 * @brief No random number generation. Add one to _myNanoEmbedded_ library.
 * @see f_random_attach()
 */
#define ERROR_GEN_TOKEN_NO_RAND_NUM_GEN 3858

//nano_base_32_2_hex
/**
 * @def ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM
 * @brief Nano address checksum invalid
 */
#define ERROR_INVALID_NANO_ADDRESS_VERIFY_CHKSUM 23

/**
 * @typedef f_nano_account_or_pk_string_to_pk_util_err_t
 * @brief Nano account or public key string error enumerator
 */
enum f_nano_account_or_pk_string_to_pk_util_err_t {
   NANO_ACCOUNT_TO_PK_OK=0,
   NANO_ACCOUNT_TO_PK_OVFL=8100,
   NANO_ACCOUNT_TO_PK_NULL_STRING,
   NANO_ACCOUNT_WRONG_PK_STR_SZ,
   NANO_ACCOUNT_WRONG_HEX_STRING,
   NANO_ACCOUNT_BASE32_CONVERT_ERROR,
   NANO_ACCOUNT_TO_PK_WRONG_ACCOUNT_LEN
};

//valid_raw_balance
/**
 * @def INVALID_RAW_BALANCE
 * @brief Invalid raw balance error
 */
#define INVALID_RAW_BALANCE 8893

//f_nano_seed_to_bip39
/**
 * @def CANT_OPEN_DICTIONARY_FILE
 * @brief Dictionary file not found or filesystem error
 */
#define CANT_OPEN_DICTIONARY_FILE 2580

/**
 * @def MISSING_PASSWORD
 * @brief Missing password error
 */
#define MISSING_PASSWORD 7153

/**
 * @def EMPTY_PASSWORD
 * @brief Empty password error
 */
#define EMPTY_PASSWORD 7169

/**
 * @def WRONG_PASSWORD
 * @brief Wrong password error
 */
#define WRONG_PASSWORD 7167

/**
 * @def ERROR_25519_IS_NOT_CANONICAL_OR_HAS_NOT_SMALL_ORDER
 * @brief Error in Elliptic Curve Ed25519: Is not canonical or has small order
 */
#define ERROR_25519_IS_NOT_CANONICAL_OR_HAS_NOT_SMALL_ORDER 12621

/**
 * @def ERROR_NANO_BLOCK
 * @brief Nano block error
 */
#define ERROR_NANO_BLOCK 13014

/**
 * @def ERROR_P2POW_BLOCK
 * @brief Nano P2PoW block error
 */
#define ERROR_P2POW_BLOCK 13015

/**
 * @def BRAINWALLET_ALLOW_MODE_NOT_ACCEPTED
 * @brief Brainwallet not accepted error
 */
#define ERROR_BRAINWALLET_ALLOW_MODE_NOT_ACCEPTED 0x3C00

/**
 * @def BRAINWALLET_MISSING_BRAINWALLET
 * @brief Missing brainwallet error
 */
#define ERROR_MISSING_BRAINWALLET 0x3C01

/**
 * @def BRAINWALLET_MISSING_SALT
 * @brief Missing salt error
 */
#define ERROR_MISSING_SALT 0x3C02

