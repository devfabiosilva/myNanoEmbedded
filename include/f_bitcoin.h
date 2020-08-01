#include <f_util.h>

#define F_BITCOIN_WIF_MAINNET (uint8_t)0x80
#define F_BITCOIN_WIF_TESTNET (uint8_t)0xEF
#define F_BITCOIN_BUF_SZ (size_t)512
#define F_MAX_BASE58_LENGTH (size_t)52 // including null char

int f_decode_b58_util(uint8_t *, size_t, size_t *, const char *);
int f_encode_b58(char *, size_t, size_t *, uint8_t *, size_t);
int f_private_key_to_wif(char *, size_t, size_t *, uint8_t, uint8_t *);
int f_wif_to_private_key(uint8_t *, unsigned char *, const char *);

