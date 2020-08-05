//#include <f_bitcoin.h>
#include <f_nano_crypto_util.h>
//qua 15 jul 2020 14:21:28 -03

const char *code_b58_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

int 

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
      k=0xFF;
      sz_tmp--;

      for (i=0;i<58;i++)
         if (text[sz_tmp]==code_b58_string[i]) {
            k=(uint8_t)i;
            break;
         }

      if (k==0xFF) {
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

