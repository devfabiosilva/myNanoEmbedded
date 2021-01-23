#include <mbedtls/bignum.h>

#define F_BITCOIN_WIF_MAINNET (uint8_t)0x80
#define F_BITCOIN_WIF_TESTNET (uint8_t)0xEF
#define F_BITCOIN_P2PKH (uint8_t)0x00 // P2PKH address
#define F_BITCOIN_T2PKH (uint8_t)0x6F // Testnet Address
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
int f_bip32_to_public_key_or_private_key(
   uint8_t *,
   int *,
   uint8_t *,
   uint8_t *,
   uint8_t *,
   uint32_t,
   const void *,
   int
);
int f_public_key_to_address(char *, size_t, size_t *, uint8_t *, uint8_t);
#define F_XPRIV_BASE58 (int)1
#define F_XPUB_BASE58 (int)2
int f_xpriv2xpub(void *, size_t, size_t *, void *, int);
int load_master_private_key(void *, unsigned char *, size_t);
int f_fingerprint(uint8_t *, uint8_t *, uint8_t *);

#define DERIVE_XPRIV_XPUB_DYN_OUT_BASE58 (int)8
#define DERIVE_XPRIV_XPUB_DYN_OUT_XPRIV (int)16
#define DERIVE_XPRIV_XPUB_DYN_OUT_XPUB (int)32

#define F_GET_XKEY_IS_BASE58 (int)0x00008000
int f_get_xkey_type(void *);
int f_derive_xpriv_or_xpub_dynamic(void **, uint8_t *, uint32_t *, void *, uint32_t, int);
int f_derive_xkey_dynamic(void **, void *, const char *, int);


