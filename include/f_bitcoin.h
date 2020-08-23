//#include <f_util.h>
#include <mbedtls/bignum.h>
//#include <string.h>
//#include <stdlib.h>

#define F_BITCOIN_WIF_MAINNET (uint8_t)0x80
#define F_BITCOIN_WIF_TESTNET (uint8_t)0xEF
#define F_BITCOIN_BUF_SZ (size_t)512
#define F_MAX_BASE58_LENGTH (size_t)112//52 // including null char
#define F_BITCOIN_SEED_GENERATOR "Bitcoin seed"

#define MAINNET_PUBLIC (size_t)0
#define MAINNET_PRIVATE (size_t)1
#define TESTNET_PUBLIC (size_t)2
#define TESTNET_PRIVATE (size_t)3

static const uint8_t F_VERSION_BYTES[][4] = {
   {0x04, 0x88, 0xB2, 0x1E}, //mainnet public
   {0x04, 0x88, 0xAD, 0xE4}, //mainnet private
   {0x04, 0x35, 0x87, 0xCF}, //testnet public
   {0x04, 0x35, 0x83, 0x94} // testnet private
};
#define F_VERSION_BYTES_IDX_LEN (size_t)(sizeof(F_VERSION_BYTES)/(4*sizeof(uint8_t)))

typedef struct f_bitcoin_serialize_t {
   uint8_t version_bytes[4];
   uint8_t master_node;
   uint8_t finger_print[4];
   uint8_t child_number[4];
   uint8_t chain_code[32];
   uint8_t sk_or_pk_data[33];
   uint8_t chksum[4];
} __attribute__((packed)) BITCOIN_SERIALIZE;

int f_decode_b58_util(uint8_t *, size_t, size_t *, const char *);
int f_encode_b58(char *, size_t, size_t *, uint8_t *, size_t);
int f_private_key_to_wif(char *, size_t, size_t *, uint8_t, uint8_t *);
int f_wif_to_private_key(uint8_t *, unsigned char *, const char *);
int f_generate_master_key(BITCOIN_SERIALIZE *, size_t, uint32_t);
int f_bitcoin_valid_bip32(BITCOIN_SERIALIZE *, int *, void *, int);
int f_uncompress_elliptic_curve(uint8_t *, size_t, size_t *, mbedtls_ecp_group_id, uint8_t *, size_t);
int f_bip32_to_public_key_or_private_key(uint8_t *, uint8_t *, uint32_t, const char *);

