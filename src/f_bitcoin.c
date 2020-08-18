//#include <f_bitcoin.h>
#include <f_nano_crypto_util.h>
//qua 15 jul 2020 14:21:28 -03

const char *code_b58_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const char DECODE_B58_LT [] = {
   0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
   0xFF, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0xFF, 0x11, 0x12, 0x13, 0x14, 0x15, 
   0xFF, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0xFF, 0xFF, 0xFF, 
   0xFF, 0xFF, 0xFF, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0xFF,
   0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39,
};

#define DECODE_B58_BUFFER_ADJUST (size_t)(2*sizeof(mbedtls_mpi))
int f_decode_b58_util(uint8_t *dec, size_t dec_sz, size_t *out_dec_sz, const char *text)
{
   int err;
   size_t sz, sz_tmp, i;
   uint8_t *buffer, k;
   mbedtls_mpi *A, *X;

   if (!(sz=strnlen(text, F_MAX_BASE58_LENGTH)))
      return 20000;

   if (sz==F_MAX_BASE58_LENGTH)
      return 20001;

   if (!(buffer=malloc(sz+DECODE_B58_BUFFER_ADJUST)))
      return 20002;

   sz_tmp=sz;

   for (;sz_tmp;) {
      sz_tmp--;

      if ((k=(uint8_t)text[sz_tmp])<(uint8_t)'1') {
         err=20009;
         goto f_decode_b58_util_EXIT1;
      }

      if (k>(uint8_t)'z') {
         err=20010;
         goto f_decode_b58_util_EXIT1;
      }

      if ((k=DECODE_B58_LT[(size_t)(k-(uint8_t)'1')])==0xFF) {
         err=20003;
         goto f_decode_b58_util_EXIT1;
      }

      buffer[sz_tmp]=k;
   }

   A=(mbedtls_mpi *)(buffer+sz);
   X=&A[1];

   mbedtls_mpi_init(A);
   mbedtls_mpi_init(X);

   if (mbedtls_mpi_lset(X, (mbedtls_mpi_sint)buffer[0])) {
      err=20004;
      goto f_decode_b58_util_EXIT2;
   }

   for (i=1;i<sz;i++) {
      if (mbedtls_mpi_mul_int(A, X, 58)) {
         err=20005;
         goto f_decode_b58_util_EXIT2;
      }

      if (mbedtls_mpi_add_int(X, A, (mbedtls_mpi_sint)buffer[i])) {
         err=20006;
         goto f_decode_b58_util_EXIT2;
      }
   }

   if ((sz_tmp=mbedtls_mpi_size(X))>dec_sz) {
      err=20007;
      goto f_decode_b58_util_EXIT2;
   }

   if (mbedtls_mpi_write_binary(X, (unsigned char *)dec, dec_sz)) {
      err=20008;
      goto f_decode_b58_util_EXIT2;
   }

   if (out_dec_sz)
      *out_dec_sz=sz_tmp;

   err=0;

f_decode_b58_util_EXIT2:
   mbedtls_mpi_free(X);
   mbedtls_mpi_free(A);

f_decode_b58_util_EXIT1:
   memset(buffer, 0, sz+DECODE_B58_BUFFER_ADJUST);
   free(buffer);
   return err;
}

#define BUFFER_ENC_B58_SZ (size_t)(F_BITCOIN_BUF_SZ+3*sizeof(mbedtls_mpi))
int f_encode_b58(char *dest, size_t dest_sz, size_t *dest_len, uint8_t *source, size_t source_sz)
{
   int err;
   uint8_t *buffer, r;
   mbedtls_mpi *A, *Q, *R;
   size_t size_tmp;

   if (!source_sz)
      return 20010;

   if (!(buffer=malloc(BUFFER_ENC_B58_SZ)))
      return 20011;

   A=(mbedtls_mpi *)(buffer+F_BITCOIN_BUF_SZ);
   Q=(mbedtls_mpi *)(((uint8_t *)A)+sizeof(mbedtls_mpi));
   R=(mbedtls_mpi *)(((uint8_t *)Q)+sizeof(mbedtls_mpi));

   mbedtls_mpi_init(A);
   mbedtls_mpi_init(Q);
   mbedtls_mpi_init(R);

   if ((err=mbedtls_mpi_read_binary(A, (unsigned char *)source, source_sz))) {
      err=20012;
      goto f_encode_b58_EXIT1;
   }

   size_tmp=0;

   for (;;) {

      if ((err=mbedtls_mpi_div_int(Q, R, A, 58)))
         goto f_encode_b58_EXIT1;

      if ((err=mbedtls_mpi_write_binary(R, (unsigned char *)&r, sizeof(r))))
         goto f_encode_b58_EXIT1;

      buffer[size_tmp++]=(uint8_t)code_b58_string[(size_t)r];

      if (size_tmp==(F_BITCOIN_BUF_SZ-1)) {
         err=20013;
         goto f_encode_b58_EXIT1;
      }

      if (mbedtls_mpi_cmp_int(Q, 0)<=0)
         break;

      if ((err=mbedtls_mpi_copy(A, Q)))
         goto f_encode_b58_EXIT1;

   }

   if ((err=f_reverse(buffer, size_tmp)))
      goto f_encode_b58_EXIT1;

   (dest_len)?(*dest_len=size_tmp):(buffer[size_tmp++]=0);

   if (size_tmp>dest_sz)
      err=20014;
   else
      memcpy(dest, buffer, size_tmp);

f_encode_b58_EXIT1:
   mbedtls_mpi_free(R);
   mbedtls_mpi_free(Q);
   mbedtls_mpi_free(A);

   memset(buffer, 0, BUFFER_ENC_B58_SZ);
   free(buffer);
   return err;
}
//https://en.bitcoin.it/wiki/Wallet_import_format
#define PRIV_KEY_WIF_BUF_SZ (size_t)(33+4+32)
int f_private_key_to_wif(char *dest, size_t dest_sz, size_t *dest_len, uint8_t wif_type, uint8_t *private_key)
{
   int err;
   uint8_t *buffer;

   if (!(buffer=malloc(PRIV_KEY_WIF_BUF_SZ)))
      return 20020;

   buffer[0]=wif_type;
   memcpy(&buffer[1], private_key, 32);
   memcpy(buffer+33, f_sha256_digest(memcpy(buffer+33+4, f_sha256_digest(buffer, 33), 32), 32), 4);

   err=f_encode_b58(dest, dest_sz, dest_len, buffer, 33+4);

f_private_key_to_wif_EXIT1:
   memset(buffer, 0, PRIV_KEY_WIF_BUF_SZ);
   free(buffer);
   return err;
}

#define WIF_FIXED_SZ (size_t)51
#define WIF_PRIV_KEY_COMPOSED_SZ (size_t)(33+4)
int f_wif_to_private_key(uint8_t *private_key, unsigned char *wif_type, const char *wif)
{
   int err;
   uint8_t *buffer;

   if (strnlen(wif, WIF_FIXED_SZ+1)!=WIF_FIXED_SZ)
      return 20030;

   if (!(buffer=malloc(WIF_PRIV_KEY_COMPOSED_SZ)))
      return 20031;

   if ((err=f_decode_b58_util(buffer, WIF_PRIV_KEY_COMPOSED_SZ, NULL, wif)))
      goto f_wif_to_private_key_EXIT1;

   memcpy(private_key, &buffer[1], 32);

   if (wif_type)
      *wif_type=(unsigned char)buffer[0];

   if (memcmp(f_sha256_digest(memcpy(buffer, f_sha256_digest(buffer, 33), 32), 32), buffer+33, 4))
      err=20032;

f_wif_to_private_key_EXIT1:
   memset(buffer, 0, WIF_PRIV_KEY_COMPOSED_SZ);
   free(buffer);
   return err;
}
////https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
#define F_BITCOIN_MASTER_KEY_BUFFER_SZ (size_t)(64+32)
int f_generate_master_key(BITCOIN_SERIALIZE *master_key, size_t version_bytes, uint32_t entropy) {
   int err;
   uint8_t *buffer, *entropy_bytes, *sha512;

   if (version_bytes>(F_VERSION_BYTES_IDX_LEN-1))
      return 20040;

   if (!(buffer=malloc(F_BITCOIN_MASTER_KEY_BUFFER_SZ)))
      return 20041;

   sha512=buffer;
   entropy_bytes=sha512+64;

   if ((err=f_verify_system_entropy_begin()))
      goto f_generate_master_key_EXIT1; 

   if ((err=f_verify_system_entropy(entropy, entropy_bytes, 32, 0)))
      goto f_generate_master_key_EXIT2;

   f_verify_system_entropy_finish();

   if ((err=f_hmac_sha512(
      (unsigned char *)sha512,
      F_BITCOIN_SEED_GENERATOR,
      sizeof(F_BITCOIN_SEED_GENERATOR)-1,
      (const unsigned char *)entropy_bytes,
      sizeof(entropy_bytes))))
      goto f_generate_master_key_EXIT2;

   if ((err=f_ecdsa_secret_key_valid(MBEDTLS_ECP_DP_SECP256K1, (unsigned char *)sha512, 32)))
      goto f_generate_master_key_EXIT2;

   memset(master_key, 0, sizeof(BITCOIN_SERIALIZE));
   memcpy(master_key->version_bytes, &F_VERSION_BYTES[version_bytes], 4);
   memcpy(&master_key->sk_or_pk_data[1], sha512, 32);
   memcpy(master_key->chain_code, sha512+32, 32);
   memcpy(master_key->chksum, f_sha256_digest(f_sha256_digest((uint8_t *)master_key, sizeof(BITCOIN_SERIALIZE)-4), 32), 4);

f_generate_master_key_EXIT2:
   memset(buffer, 0, F_BITCOIN_MASTER_KEY_BUFFER_SZ);
f_generate_master_key_EXIT1:
   free(buffer);
   return err;
}

// return 0 if is valid, otherwise invalid
// output (optional) copy bip32 to binary if valid. It can be NULL
// bip32 (binary or base58 encoded)
// bip32_enc_base58. If bip32 is encoded base58 then non zero, 0 if binary
int f_bitcoin_valid_bip32(BITCOIN_SERIALIZE *output, int *type, void *bip32, int bip32_enc_base58)
{
   int err;
   BITCOIN_SERIALIZE *p;
   size_t sz_tmp;

   if (bip32_enc_base58) {
      if (!(p=malloc(sizeof(BITCOIN_SERIALIZE))))
         return 20060;

      if ((err=f_decode_b58_util((uint8_t *)p, sizeof(BITCOIN_SERIALIZE), &sz_tmp, (const char *)bip32)))
         goto f_bitcoin_valid_bip32_EXIT1;

      if (sz_tmp!=sizeof(BITCOIN_SERIALIZE)) {
         err=20061;
         goto f_bitcoin_valid_bip32_EXIT1;
      }
   } else
      p=(BITCOIN_SERIALIZE *)bip32;

   err=20062;

   for (sz_tmp=0;sz_tmp<F_VERSION_BYTES_IDX_LEN;)
      if (memcmp(p, F_VERSION_BYTES[sz_tmp++], 4)==0) {
         err=0;
         break;
      }

   if (err)
      goto f_bitcoin_valid_bip32_EXIT2;

   if ((sz_tmp&1)==0) {
      if (p->sk_or_pk_data[0]) {
         err=20063;
         goto f_bitcoin_valid_bip32_EXIT2;
      }

      if ((err=f_ecdsa_secret_key_valid(MBEDTLS_ECP_DP_SECP256K1, (unsigned char *)&p->sk_or_pk_data[1], 32)))
         goto f_bitcoin_valid_bip32_EXIT2;
   }
//https://bitcointalk.org/index.php?topic=129652.0
//https://github.com/ARMmbed/mbedtls/pull/1608
/*
   if (sz_tmp&1) {
      if ((err=f_ecdsa_public_key_valid(MBEDTLS_ECP_DP_SECP256K1, (unsigned char *)p->sk_or_pk_data, 33)))
         goto f_bitcoin_valid_bip32_EXIT2;
   } else {
      if (p->sk_or_pk_data[0]) {
         err=20063;
         goto f_bitcoin_valid_bip32_EXIT2;
      }

      if ((err=f_ecdsa_secret_key_valid(MBEDTLS_ECP_DP_SECP256K1, (unsigned char *)&p->sk_or_pk_data[1], 32)))
         goto f_bitcoin_valid_bip32_EXIT2;
   }
*/
   if (memcmp(f_sha256_digest(f_sha256_digest((uint8_t *)p, sizeof(BITCOIN_SERIALIZE)-4), 32), p->chksum, 4)) {
      err=20064;
      goto f_bitcoin_valid_bip32_EXIT2;
   }

   if (output)
      memcpy(output, p, sizeof(BITCOIN_SERIALIZE));

   if (type)
      *type=(int)sz_tmp;

f_bitcoin_valid_bip32_EXIT2:
   if (bip32_enc_base58) {
f_bitcoin_valid_bip32_EXIT1:
      memset(p, 0, sizeof(BITCOIN_SERIALIZE));
      free(p);
   }

   return err;
}

#define BIP32_TO_PK_SK_SZ (size_t)(sizeof(BITCOIN_SERIALIZE)+65+64+f_ecdsa_key_pair)
int f_bip32_to_public_key_or_private_key(uint8_t *sk_or_pk, uint32_t index, const char *bip32)
{
   int err, type;
   uint8_t *buffer;
   BITCOIN_SERIALIZE *bitcoin_bip32_ser;
   f_ecdsa_key_pair *key_pair;

   if (!(bitcoin_bip32_ser=malloc(BIP32_TO_PK_SK_SZ)))
      return 20070;

   bitcoin_bip32_ser=(BITCOIN_SERIALIZE *)buffer;

   if ((err=f_bitcoin_valid_bip32(bitcoin_bip32_ser, &type, (void *)bip32, 1)))
      goto f_bip32_to_public_key_or_private_key_EXIT1;

   if ((*((uint32_t *)bitcoin_bip32_ser->chksum)=index)>=(2<<31)) {
      err=20071;
      goto f_bip32_to_public_key_or_private_key_EXIT1;
   }

   if ((err=f_reverse((unsigned char *)bitcoin_bip32_ser->chksum, sizeof(bitcoin_bip32_ser->chksum))))
      goto f_bip32_to_public_key_or_private_key_EXIT1;

   if ((err=f_hmac_sha512(((unsigned char *)&bitcoin_bip32_ser[1])+65, (const unsigned char *)bitcoin_bip32_ser->chain_code, sizeof(bitcoin_bip32_ser->chain_code),
      (const unsigned char *)bitcoin_bip32_ser->sk_or_pk_data, sizeof(bitcoin_bip32_ser->sk_or_pk_data)+sizeof(bitcoin_bip32_ser->chksum))))
      goto f_bip32_to_public_key_or_private_key_EXIT1;

   memset(key_pair=(f_ecdsa_key_pair *)(buffer+BIP32_TO_PK_SK_SZ-sizeof(f_ecdsa_key_pair)), 0, sizeof(f_ecdsa_key_pair));
   f_ecdsa_key_pair->gid=MBEDTLS_ECP_DP_SECP256K1;

   if (type&1) {
      if ((err=f_uncompress_elliptic_curve((uint8_t *)&bitcoin_bip32_ser[1], 65, NULL, MBEDTLS_ECP_DP_SECP256K1, bitcoin_bip32_ser->sk_or_pk_data, 
         sizeof(bitcoin_bip32_ser->sk_or_pk_data)))) goto f_bip32_to_public_key_or_private_key_EXIT1;
// to be continued...
   }

f_bip32_to_public_key_or_private_key_EXIT1:
   memset(buffer, 0, BIP32_TO_PK_SK_SZ);
   free(buffer);

   return err;
}

