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
#define PRIV_KEY_WIF_BUF_SZ (size_t)(33+4)
int f_private_key_to_wif(char *dest, size_t dest_sz, size_t *dest_len, uint8_t wif_type, uint8_t *private_key)
{
   int err;
   uint8_t *buffer, *hash;

   if (!(buffer=malloc(PRIV_KEY_WIF_BUF_SZ)))
      return 20020;

   buffer[0]=wif_type;
   memcpy(&buffer[1], private_key, 32);

   if (f_sha256_digest((void **)&hash, 0, buffer, 33)) {
      err=20021;
      goto f_private_key_to_wif_EXIT1;
   }

   if (f_sha256_digest((void **)&hash, 0, hash, 32)) {
      err=20022;
      goto f_private_key_to_wif_EXIT1;
   }

   memcpy(buffer+33, hash, 4);
//   memcpy(buffer+33, f_sha256_digest(f_sha256_digest(buffer, 33), 32), 4);

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
   uint8_t *buffer, *hash;

   if (strnlen(wif, WIF_FIXED_SZ+1)!=WIF_FIXED_SZ)
      return 20030;

   if (!(buffer=malloc(WIF_PRIV_KEY_COMPOSED_SZ)))
      return 20031;

   if ((err=f_decode_b58_util(buffer, WIF_PRIV_KEY_COMPOSED_SZ, NULL, wif)))
      goto f_wif_to_private_key_EXIT1;

   if ((buffer[0]!=F_BITCOIN_WIF_MAINNET)&&(buffer[0]!=F_BITCOIN_WIF_TESTNET)) {
      err=20032;
      goto f_wif_to_private_key_EXIT1;
   }

   if (f_sha256_digest((void **)&hash, 0, buffer, 33)) {
      err=20033;
      goto f_wif_to_private_key_EXIT1;
   }

   if (f_sha256_digest((void **)&hash, 0, hash, 32)) {
      err=20034;
      goto f_wif_to_private_key_EXIT1;
   }

   if (memcmp(hash, buffer+33, 4)) {
//   if (memcmp(f_sha256_digest(f_sha256_digest(buffer, 33), 32), buffer+33, 4)) {
      err=20035;
      goto f_wif_to_private_key_EXIT1;
   }

   memcpy(private_key, &buffer[1], 32);

   if (wif_type)
      *wif_type=(unsigned char)buffer[0];

   //if (memcmp(f_sha256_digest(memcpy(buffer, f_sha256_digest(buffer, 33), 32), 32), buffer+33, 4))

f_wif_to_private_key_EXIT1:
   memset(buffer, 0, WIF_PRIV_KEY_COMPOSED_SZ);
   free(buffer);
   return err;
}
////https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
#define F_BITCOIN_MASTER_KEY_BUFFER_SZ (size_t)(64+32)
int f_generate_master_key(BITCOIN_SERIALIZE *master_key, size_t version_bytes, uint32_t entropy) {
   int err;
   uint8_t *buffer, *entropy_bytes, *sha512, *hash;

   if (version_bytes>(F_VERSION_BYTES_IDX_LEN-1))
      return 20040;

   if (!(buffer=malloc(F_BITCOIN_MASTER_KEY_BUFFER_SZ)))
      return 20041;

   sha512=buffer;
   entropy_bytes=sha512+64;

   if ((err=f_verify_system_entropy_begin()))
      goto f_generate_master_key_EXIT1; 

   /*if ((err=f_verify_system_entropy(entropy, entropy_bytes, 32, 0)))
      goto f_generate_master_key_EXIT2;*/
   err=f_verify_system_entropy(entropy, entropy_bytes, 32, 0);

   f_verify_system_entropy_finish();

   if (err)
      goto f_generate_master_key_EXIT2;

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

   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)master_key, sizeof(BITCOIN_SERIALIZE)-4))) 
      goto f_generate_master_key_EXIT2;

   if ((err=f_sha256_digest((void **)&hash, 0, hash, 32)))
      goto f_generate_master_key_EXIT2;

//   memcpy(master_key->chksum, f_sha256_digest(f_sha256_digest((uint8_t *)master_key, sizeof(BITCOIN_SERIALIZE)-4), 32), 4);
   memcpy(master_key->chksum, hash, 4);

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
   uint8_t *hash;

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

   if (f_sha256_digest((void **)&hash, 0, (uint8_t *)p, sizeof(BITCOIN_SERIALIZE)-4)) { 
      err=20064;
      goto f_bitcoin_valid_bip32_EXIT2;
   }

   if (f_sha256_digest((void **)&hash, 0, hash, 32)) {
      err=20065;
      goto f_bitcoin_valid_bip32_EXIT2;
   }

   if (memcmp(hash, p->chksum, 4)) {
//   if (memcmp(f_sha256_digest(f_sha256_digest((uint8_t *)p, sizeof(BITCOIN_SERIALIZE)-4), 32), p->chksum, 4)) {
      err=20066;
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

//inline
int load_master_private_key(void *handle, unsigned char *data, size_t data_sz)
{
   if (data_sz!=32)
      return 1;

   memcpy(data, handle, 32);
   return 0;
}

typedef struct bip32_sk_t {
   mbedtls_mpi kpar;
   mbedtls_mpi ki;
   mbedtls_mpi Result;
} __attribute__((packed)) BIP32_SK;

typedef struct bip32_pk_t {
   mbedtls_mpi m;
   mbedtls_ecp_point Kpar;
   mbedtls_ecp_point Result;
} __attribute__((packed)) BIP32_PK;

typedef union u_pk_sk_t {
   BIP32_PK PK;
   BIP32_SK SK;
} __attribute__((packed)) UNION_PK_SK;


#define BIP32_TO_PK_SK_SZ (size_t)(sizeof(BITCOIN_SERIALIZE)+65+64+sizeof(mbedtls_ecp_group)+sizeof(UNION_PK_SK)+sizeof(mbedtls_ecdsa_context)+sizeof(f_ecdsa_key_pair))
int f_bip32_to_public_key_or_private_key(
   uint8_t *sk_or_pk,
   int *xtype,
   uint8_t *depth,
   uint8_t *fingerprint,
   uint8_t *chain_code,
   uint32_t index,
   const void *bip32,
   int bip32_enc_base58
)
{
//chain_code is optional
   int err, type;
   uint8_t *buffer;
   size_t size_tmp;
   BITCOIN_SERIALIZE *bitcoin_bip32_ser;
   f_ecdsa_key_pair *key_pair;
   UNION_PK_SK *PK_SK;
   mbedtls_ecp_group *grp;

   if (!(buffer=malloc(BIP32_TO_PK_SK_SZ)))
      return 20070;

   bitcoin_bip32_ser=(BITCOIN_SERIALIZE *)buffer;

   if ((err=f_bitcoin_valid_bip32(bitcoin_bip32_ser, &type, (void *)bip32, bip32_enc_base58)))
      goto f_bip32_to_public_key_or_private_key_EXIT1;

   if ((*((uint32_t *)bitcoin_bip32_ser->chksum)=index)>=(1<<31)) {
      err=20071;
      goto f_bip32_to_public_key_or_private_key_EXIT1;
   }

   if ((err=f_reverse((unsigned char *)bitcoin_bip32_ser->chksum, sizeof(bitcoin_bip32_ser->chksum))))
      goto f_bip32_to_public_key_or_private_key_EXIT1;

   memset(key_pair=((f_ecdsa_key_pair *)((uint8_t *)buffer+BIP32_TO_PK_SK_SZ-sizeof(f_ecdsa_key_pair))), 0, sizeof(f_ecdsa_key_pair));
   key_pair->gid=MBEDTLS_ECP_DP_SECP256K1;
   mbedtls_ecdsa_init(key_pair->ctx=((mbedtls_ecdsa_context *)((uint8_t *)&bitcoin_bip32_ser[1]+65+64+sizeof(mbedtls_ecp_group)+sizeof(UNION_PK_SK))));

   if (type&1) {
      if ((err=f_uncompress_elliptic_curve((uint8_t *)&bitcoin_bip32_ser[1], 65, NULL, MBEDTLS_ECP_DP_SECP256K1, bitcoin_bip32_ser->sk_or_pk_data, 
         sizeof(bitcoin_bip32_ser->sk_or_pk_data)))) goto f_bip32_to_public_key_or_private_key_EXIT2;

      if (fingerprint)
         if ((err=f_fingerprint(NULL, fingerprint, (uint8_t *)&bitcoin_bip32_ser[1])))
            goto f_bip32_to_public_key_or_private_key_EXIT2;

   } else {
      if ((err=f_gen_ecdsa_key_pair(key_pair, MBEDTLS_ECP_PF_COMPRESSED, load_master_private_key, (void *)&bitcoin_bip32_ser->sk_or_pk_data[1])))
         goto f_bip32_to_public_key_or_private_key_EXIT2;

      if (key_pair->public_key_sz!=sizeof(bitcoin_bip32_ser->sk_or_pk_data)) {
         err=20072;
         goto f_bip32_to_public_key_or_private_key_EXIT2;
      }

      if (fingerprint)
         if ((err=f_fingerprint(NULL, fingerprint, key_pair->public_key)))
            goto f_bip32_to_public_key_or_private_key_EXIT2;

      memcpy((uint8_t *)&bitcoin_bip32_ser[1], &bitcoin_bip32_ser->sk_or_pk_data[1], 32);
      memcpy(bitcoin_bip32_ser->sk_or_pk_data, key_pair->public_key, sizeof(bitcoin_bip32_ser->sk_or_pk_data));
   }

   if ((err=f_hmac_sha512(((unsigned char *)&bitcoin_bip32_ser[1])+65, (const unsigned char *)bitcoin_bip32_ser->chain_code, sizeof(bitcoin_bip32_ser->chain_code),
      (const unsigned char *)bitcoin_bip32_ser->sk_or_pk_data, sizeof(bitcoin_bip32_ser->sk_or_pk_data)+sizeof(bitcoin_bip32_ser->chksum))))
      goto f_bip32_to_public_key_or_private_key_EXIT2;

   mbedtls_ecp_group_init(grp=(mbedtls_ecp_group *)(((uint8_t  *)&bitcoin_bip32_ser[1])+65+64));
   //if ((err=mbedtls_ecp_group_load(grp=(mbedtls_ecp_group *)(((uint8_t  *)&bitcoin_bip32_ser[1])+65+64), MBEDTLS_ECP_DP_SECP256K1)))
   if ((err=mbedtls_ecp_group_load(grp, MBEDTLS_ECP_DP_SECP256K1)))
      goto f_bip32_to_public_key_or_private_key_EXIT2;

   PK_SK=(UNION_PK_SK *)(((uint8_t *)grp)+sizeof(mbedtls_ecp_group));

   if (type&1) {
      mbedtls_mpi_init(&PK_SK->PK.m);
      mbedtls_ecp_point_init(&PK_SK->PK.Kpar);
      mbedtls_ecp_point_init(&PK_SK->PK.Result);

      if (mbedtls_ecp_point_read_binary(grp, &PK_SK->PK.Kpar, (const unsigned char *)&bitcoin_bip32_ser[1], 65)) {
         err=20074;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }

      if (mbedtls_ecdsa_genkey(key_pair->ctx, key_pair->gid, load_master_private_key, (void *)(((uint8_t *)&bitcoin_bip32_ser[1])+65))) {
         err=20075;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }
      // In case parse256(IL) ≥ n or Ki is the point at infinity, the resulting key is invalid, and one should proceed with the next value for i.
 // Ref.: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
///////BEGIN

      if (mbedtls_ecp_is_zero(&key_pair->ctx->Q)) {
         err=20089;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }

      if (mbedtls_mpi_read_binary(&PK_SK->PK.m, (((uint8_t *)&bitcoin_bip32_ser[1])+65), 32)) {
         err=20090;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }

      if (mbedtls_mpi_cmp_mpi(&grp->N, &PK_SK->PK.m)<1) {
         err=20091;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }
///
///////END

      if (mbedtls_mpi_lset(&PK_SK->PK.m, (mbedtls_mpi_sint)1)) {
         err=20073;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }

      if (mbedtls_ecp_muladd(grp, &PK_SK->PK.Result, &PK_SK->PK.m, &key_pair->ctx->Q, &PK_SK->PK.m, &PK_SK->PK.Kpar)) {
         err=20076;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }

      if (mbedtls_ecp_check_pubkey(grp, &PK_SK->PK.Result)) {
         err=20077;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }

      if (mbedtls_ecp_point_write_binary(grp, &PK_SK->PK.Result, MBEDTLS_ECP_PF_COMPRESSED, &size_tmp, (unsigned char *)sk_or_pk,//bitcoin_bip32_ser->sk_or_pk_data,
         sizeof(bitcoin_bip32_ser->sk_or_pk_data))) {
         err=20078;
         goto f_bip32_to_public_key_or_private_key_EXIT4;
      }

      err=0;
      if (size_tmp!=sizeof(bitcoin_bip32_ser->sk_or_pk_data))
         err=20079;

      goto f_bip32_to_public_key_or_private_key_EXIT4;
   } else {
      mbedtls_mpi_init(&PK_SK->SK.kpar);
      mbedtls_mpi_init(&PK_SK->SK.ki);
      mbedtls_mpi_init(&PK_SK->SK.Result);

      if (mbedtls_mpi_read_binary(&PK_SK->SK.kpar, (const unsigned char *)&bitcoin_bip32_ser[1], 32)) {
         err=20080;
         goto f_bip32_to_public_key_or_private_key_EXIT5;
      }

      if (mbedtls_mpi_read_binary(&PK_SK->SK.ki, (const unsigned char *)(((uint8_t *)&bitcoin_bip32_ser[1])+65), 32)) {
         err=20083;
         goto f_bip32_to_public_key_or_private_key_EXIT5;
      }

      // In case parse256(IL) ≥ n or ki = 0, the resulting key is invalid, and one should proceed with the next value for i. (Note: this has probability lower than 1 in 2^127.) // Ref.: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
///////BEGIN
      if (mbedtls_mpi_cmp_int(&PK_SK->SK.ki, 0)==0) {
         err=20087;
         goto f_bip32_to_public_key_or_private_key_EXIT5;
      }

      if (mbedtls_mpi_cmp_mpi(&grp->N, &PK_SK->SK.ki)<1) {
         err=20088;
         goto f_bip32_to_public_key_or_private_key_EXIT5;
      }
///////END
///
      if (mbedtls_mpi_add_mpi(&PK_SK->SK.Result, &PK_SK->SK.kpar, &PK_SK->SK.ki)) {
         err=20084;
         goto f_bip32_to_public_key_or_private_key_EXIT5;
      }

      if (mbedtls_mpi_mod_mpi(&PK_SK->SK.Result, &PK_SK->SK.Result, &grp->N)) {
         err=20082;
         goto f_bip32_to_public_key_or_private_key_EXIT5;
      }
///
      if (mbedtls_ecp_check_privkey(grp, &PK_SK->SK.Result)) {
         err=20085;
         goto f_bip32_to_public_key_or_private_key_EXIT5;
      }

      err=0;
      sk_or_pk[0]=0;

      if (mbedtls_mpi_write_binary(&PK_SK->SK.Result, (unsigned char *)&sk_or_pk[1], 32))
         err=20086;

   }

f_bip32_to_public_key_or_private_key_EXIT5:
   mbedtls_mpi_free(&PK_SK->SK.Result);
   mbedtls_mpi_free(&PK_SK->SK.ki);
   mbedtls_mpi_free(&PK_SK->SK.kpar);
   goto f_bip32_to_public_key_or_private_key_EXIT3;

f_bip32_to_public_key_or_private_key_EXIT4:
   mbedtls_ecp_point_free(&PK_SK->PK.Kpar);
   mbedtls_ecp_point_free(&PK_SK->PK.Result);
   mbedtls_mpi_free(&PK_SK->PK.m);

f_bip32_to_public_key_or_private_key_EXIT3:
   mbedtls_ecp_group_free(grp);

   if (err==0) {
      if (chain_code)
         memcpy(chain_code, (((uint8_t *)&bitcoin_bip32_ser[1])+65+32), 32);

      if (xtype)
         *xtype=type;

      if (depth)
         *depth=bitcoin_bip32_ser->master_node;
   }

f_bip32_to_public_key_or_private_key_EXIT2:
   mbedtls_ecdsa_free(key_pair->ctx);

f_bip32_to_public_key_or_private_key_EXIT1:
   memset(buffer, 0, BIP32_TO_PK_SK_SZ);
   free(buffer);

   return err;
}
//https://en.bitcoin.it/wiki/Address
//https://en.bitcoin.it/wiki/Base58Check_encoding
//https://en.bitcoin.it/wiki/List_of_address_prefixes
//#define PK2B58ADDR_BUF_SZ (size_t)(1+65)
#define PK2B58ADDR_BUF_SZ (size_t)(1+33)
int f_public_key_to_address(char *dest, size_t dest_sz, size_t *olen, uint8_t *public_key, uint8_t pk_type)
{
   int err;
   uint8_t *buf, *ripemd160, *hash;
   size_t sz_tmp;

   if (!(buf=malloc(PK2B58ADDR_BUF_SZ)))
      return 20100;
/*
   // BUG Fixed at Sun apr 25 14:04:51 -03 2021 due to wrong reference: https://en.bitcoin.it/wiki/File:PubKeyToAddr.png (wrong implementation)
   // Correct reference: https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
   if (public_key[0]==0x04) memcpy(&buf[1], public_key, 65);
   else if ((err=f_uncompress_elliptic_curve(&buf[1], PK2B58ADDR_BUF_SZ-1, NULL, MBEDTLS_ECP_DP_SECP256K1, public_key, 33)))
      goto f_public_key_to_address_EXIT1;

   buf[0]=pk_type;

   if (f_sha256_digest((void **)&hash, 0, &buf[1], 65)) { 
      err=20101;
      goto f_public_key_to_address_EXIT2;
   }
*/

// begin correction BUG Fixed at Sun apr 25 14:04:51 -03 2021

   if (public_key[0]==0x04) {
      buf[1]=0x02+(public_key[64]&0x01);
      memcpy(&buf[2], &public_key[1], 32);

   } else if ((public_key[0]==0x03)||(public_key[0]==0x02))
      memcpy(&buf[1], public_key, 33);
   else {
      err=20101;
      goto f_public_key_to_address_EXIT2;
   }

//   buf[0]=pk_type;

   if (f_sha256_digest((void **)&hash, 0, &buf[1], 33)) { 
      err=20101;
      goto f_public_key_to_address_EXIT2;
   }
// End correction

   if (!(ripemd160=f_ripemd160((const uint8_t *)hash, 32))) {
      err=20102;
      goto f_public_key_to_address_EXIT2;
   }

   memcpy(&buf[1], ripemd160, 20);

   buf[0]=pk_type;

   if (f_sha256_digest((void **)&hash, 0, buf, 20+1)) { 
      err=20103;
      goto f_public_key_to_address_EXIT2;
   }

   if (f_sha256_digest((void **)&hash, 0, hash, 32)) {
      err=20104;
      goto f_public_key_to_address_EXIT2;
   }

   memcpy(buf+20+1, hash, 4);

   if (buf[0])
      sz_tmp=0;
   else {
      *(dest++)='1';
      dest_sz--;
      sz_tmp=1;
   }

   if ((err=f_encode_b58(dest, dest_sz, olen, buf+sz_tmp, 1+20+4-sz_tmp))==0)
      if (olen)
         *olen+=sz_tmp;

f_public_key_to_address_EXIT2:
   memset(buf, 0, PK2B58ADDR_BUF_SZ);
f_public_key_to_address_EXIT1:
   free(buf);

   return err;
}

#define XPRIV2PUB_BUF_SZ (size_t)sizeof(BITCOIN_SERIALIZE)+sizeof(f_ecdsa_key_pair)
int f_xpriv2xpub(void *xpub, size_t xpub_sz, size_t *xpub_len, void *xpriv, int enc)
{
   int err, type;
   uint8_t *buf, *hash;
   f_ecdsa_key_pair *key_pair;

   if (!(buf=malloc(XPRIV2PUB_BUF_SZ)))
      return 20130;

   if ((err=f_bitcoin_valid_bip32((BITCOIN_SERIALIZE *)buf, &type, xpriv, enc&F_XPRIV_BASE58)))
      goto f_xpriv2xpub_EXIT1;

   if (type&1) {
      err=20131;
      goto f_xpriv2xpub_EXIT1;
   }

   (key_pair=(f_ecdsa_key_pair *)(buf+sizeof(BITCOIN_SERIALIZE)))->gid=MBEDTLS_ECP_DP_SECP256K1;
   key_pair->ctx=NULL;

   if ((err=f_gen_ecdsa_key_pair(key_pair, MBEDTLS_ECP_PF_COMPRESSED, load_master_private_key, (void *)&((BITCOIN_SERIALIZE *)buf)->sk_or_pk_data[1])))
      goto f_xpriv2xpub_EXIT1;

   if (key_pair->public_key_sz!=sizeof(((BITCOIN_SERIALIZE *)0)->sk_or_pk_data)) {
      err=20132;
      goto f_xpriv2xpub_EXIT1;
   }

   memcpy(((BITCOIN_SERIALIZE *)buf)->version_bytes, F_VERSION_BYTES[(size_t)type-2], sizeof(((BITCOIN_SERIALIZE *)0)->version_bytes));
   memcpy(((BITCOIN_SERIALIZE *)buf)->sk_or_pk_data, key_pair->public_key, sizeof(((BITCOIN_SERIALIZE *)0)->sk_or_pk_data));

   if ((err=f_sha256_digest((void **)&hash, 0, buf, sizeof(BITCOIN_SERIALIZE)-4))) 
      goto f_xpriv2xpub_EXIT1;

   if ((err=f_sha256_digest((void **)&hash, 0, hash, 32)))
      goto f_xpriv2xpub_EXIT1;

   memcpy(((BITCOIN_SERIALIZE *)buf)->chksum, hash, sizeof(((BITCOIN_SERIALIZE *)0)->chksum));

   if (enc&F_XPUB_BASE58) {
      err=f_encode_b58((char *)xpub, xpub_sz, xpub_len, buf, sizeof(BITCOIN_SERIALIZE));
      goto f_xpriv2xpub_EXIT1;
   }

   if (sizeof(BITCOIN_SERIALIZE)>xpub_sz) {
      err=20133;
      goto f_xpriv2xpub_EXIT1;
   }

   memcpy(xpub, buf, sizeof(BITCOIN_SERIALIZE));

   if (xpub_len)
      *xpub_len=sizeof(BITCOIN_SERIALIZE);

f_xpriv2xpub_EXIT1:
   memset(buf, 0, XPRIV2PUB_BUF_SZ);
   free(buf);
   return err;
}

#define F_FINGERPRINT_BUFFER (size_t)65
// Out expanded pk can be NULL
int f_fingerprint(uint8_t *out_expanded_pk, uint8_t *fingerprint, uint8_t *public_key)
{
   int err;
   uint8_t *buf, *hash, *ripemd160;

   if (out_expanded_pk)
      buf=out_expanded_pk;
   else if (!(buf=malloc(F_FINGERPRINT_BUFFER)))
      return 20140;

   if (public_key[0]==0x04) memcpy(buf, public_key, F_FINGERPRINT_BUFFER);
   else if ((err=f_uncompress_elliptic_curve(buf, F_FINGERPRINT_BUFFER, NULL, MBEDTLS_ECP_DP_SECP256K1, public_key, 33)))
      goto f_fingerprint_EXIT1;

   if (f_sha256_digest((void **)&hash, 0, buf, F_FINGERPRINT_BUFFER)) { 
      err=20141;
      goto f_fingerprint_EXIT1;
   }

   err=20142;
   if ((ripemd160=f_ripemd160((const uint8_t *)hash, 32))) {
      err=0;
      memcpy(fingerprint, ripemd160, 4);
   }

f_fingerprint_EXIT1:
   if (!out_expanded_pk)
      free(buf);

   return err;
}

int f_get_xkey_type(void *xkey)
{

   if (memcmp(xkey, "xpub", 4)==0)
      return (F_GET_XKEY_IS_BASE58|(MAINNET_PUBLIC+1));

   if (memcmp(xkey, F_VERSION_BYTES[MAINNET_PUBLIC], 4)==0)
      return (MAINNET_PUBLIC+1);

   if (memcmp(xkey, "xprv", 4)==0)
      return (F_GET_XKEY_IS_BASE58|(MAINNET_PRIVATE+1));

   if (memcmp(xkey, F_VERSION_BYTES[MAINNET_PRIVATE], 4)==0)
      return MAINNET_PRIVATE+1;

   if (memcmp(xkey, "tpub", 4)==0)
      return (F_GET_XKEY_IS_BASE58|(TESTNET_PUBLIC+1));

   if (memcmp(xkey, F_VERSION_BYTES[TESTNET_PUBLIC], 4)==0)
      return TESTNET_PUBLIC+1;

   if (memcmp(xkey, "tprv", 4)==0)
      return (F_GET_XKEY_IS_BASE58|(TESTNET_PRIVATE+1));

   if (memcmp(xkey, F_VERSION_BYTES[TESTNET_PRIVATE], 4)==0)
      return TESTNET_PRIVATE+1;

   return 0;
}

#define DERIVE_XPRIV_XPUB_DYN_IN_BASE58 (int)4
#define DERIVE_XPRIV_XPUB_DYN_BUFFER_SZ (size_t)(2*sizeof(BITCOIN_SERIALIZE))
#define DERIVE_DYN_SZ (size_t)128
int f_derive_xpriv_or_xpub_dynamic(void **out, uint8_t *depth, uint32_t *fingerprint, void *in_xpriv_or_xpub, uint32_t index, int in_out_type)
{
   int err, type;
   void *buffer, *btc_out, *p;
   BITCOIN_SERIALIZE *btc_ser_out;
   uint8_t *hash;

   *out=NULL;
   if ((type=f_get_xkey_type(in_xpriv_or_xpub))==0)
      return 20150;

   if (!(buffer=malloc(DERIVE_XPRIV_XPUB_DYN_BUFFER_SZ)))
      return 20151;

   if (type&F_GET_XKEY_IS_BASE58)
      in_out_type|=DERIVE_XPRIV_XPUB_DYN_IN_BASE58;

   if (type&1) {
      if (in_out_type&DERIVE_XPRIV_XPUB_DYN_OUT_XPRIV) {
         err=20152;
         goto f_derive_xpriv_or_xpub_dynamic_EXIT1;
      }

      if (!(in_out_type&DERIVE_XPRIV_XPUB_DYN_OUT_XPUB)) {
         err=20153;
         goto f_derive_xpriv_or_xpub_dynamic_EXIT1;
      }

      p=in_xpriv_or_xpub;

   } else {

      if (in_out_type&DERIVE_XPRIV_XPUB_DYN_OUT_XPRIV)
         p=in_xpriv_or_xpub;
      else if (in_out_type&DERIVE_XPRIV_XPUB_DYN_OUT_XPUB) {
         if ((err=f_xpriv2xpub((void *)(p=(BITCOIN_SERIALIZE *)buffer), sizeof(BITCOIN_SERIALIZE), NULL, in_xpriv_or_xpub,
            (in_out_type&DERIVE_XPRIV_XPUB_DYN_IN_BASE58)?F_XPRIV_BASE58:0)))
            goto f_derive_xpriv_or_xpub_dynamic_EXIT1;

         in_out_type&=(~(DERIVE_XPRIV_XPUB_DYN_IN_BASE58));
      } else {
         err=20154;
         goto f_derive_xpriv_or_xpub_dynamic_EXIT1;
      }

   }

   btc_ser_out=&((BITCOIN_SERIALIZE *)buffer)[1];

   if ((err=f_bip32_to_public_key_or_private_key(btc_ser_out->sk_or_pk_data, &type, &btc_ser_out->master_node, btc_ser_out->finger_print, btc_ser_out->chain_code, 
      index, (const void *)p, in_out_type&DERIVE_XPRIV_XPUB_DYN_IN_BASE58))) goto f_derive_xpriv_or_xpub_dynamic_EXIT1;

   if (!(++btc_ser_out->master_node)) {
      err=20155;
      goto f_derive_xpriv_or_xpub_dynamic_EXIT1;
   }

   memcpy(btc_ser_out->version_bytes, F_VERSION_BYTES[(size_t)(type-1)], sizeof(((BITCOIN_SERIALIZE *)0)->version_bytes));

   *((uint32_t *)btc_ser_out->child_number)=index;

   if ((err=f_reverse((unsigned char *)btc_ser_out->child_number, sizeof(((BITCOIN_SERIALIZE *)0)->child_number))))
      goto f_derive_xpriv_or_xpub_dynamic_EXIT1;

   if ((err=f_sha256_digest((void **)&hash, 0, (uint8_t *)btc_ser_out, sizeof(BITCOIN_SERIALIZE)-4))) 
      goto f_derive_xpriv_or_xpub_dynamic_EXIT1;

   if ((err=f_sha256_digest((void **)&hash, 0, hash, 32)))
      goto f_derive_xpriv_or_xpub_dynamic_EXIT1;

   memcpy(btc_ser_out->chksum, hash, sizeof(((BITCOIN_SERIALIZE *)0)->chksum));

   if (!(*out=malloc(DERIVE_DYN_SZ))) {
      err=20156;
      goto f_derive_xpriv_or_xpub_dynamic_EXIT1;
   }

   if (in_out_type&DERIVE_XPRIV_XPUB_DYN_OUT_BASE58) {
      if ((err=f_encode_b58((char *)*out, DERIVE_DYN_SZ, NULL, (uint8_t *)btc_ser_out, sizeof(BITCOIN_SERIALIZE))))
         goto f_derive_xpriv_or_xpub_dynamic_EXIT2;
   } else
      memcpy(*out, btc_ser_out, sizeof(BITCOIN_SERIALIZE));

   if (depth)
      *depth=btc_ser_out->master_node;

   if (fingerprint)
      *fingerprint=*((uint32_t *)btc_ser_out->finger_print);

   goto f_derive_xpriv_or_xpub_dynamic_EXIT1;

f_derive_xpriv_or_xpub_dynamic_EXIT2:
   memset(*out, 0, DERIVE_DYN_SZ);
   free(*out);
   *out=NULL;

f_derive_xpriv_or_xpub_dynamic_EXIT1:
   memset(buffer, 0, DERIVE_XPRIV_XPUB_DYN_BUFFER_SZ);
   free(buffer);

   return err;
}

static int f_parse_index_string_to_uint32_t_util(uint32_t *value, const char *str_val, size_t str_val_sz)
{
   int err;
   char out[11];
   unsigned long int value_out;

   if (str_val_sz>(sizeof(out)-1))
      return 900;

   memcpy(out, str_val, str_val_sz);
   out[str_val_sz]=0;

   if (f_convert_to_long_int(&value_out, out, sizeof(out)))
      return 901;

   if (value_out>(unsigned long int)((uint32_t)((int)-1)))
      return 902;

   *value=(uint32_t)value_out;

   return 0;
}

#define F_DERIVE_M_DEPTH_MAX_SZ (size_t)3072
int f_derive_xkey_dynamic(void **out, void *mkey, const char *m_depth, int out_type)
{
   int err;
   char *p1, *p2;
   uint32_t index;
   size_t val_sz;
   void *out1, *out2;

   *out=NULL;
   if ((val_sz=strnlen(m_depth, F_DERIVE_M_DEPTH_MAX_SZ))==F_DERIVE_M_DEPTH_MAX_SZ)
      return 20160;

   if (val_sz==0)
      return 20161;

   p1=(char *)m_depth;

   if (*(p1++)!='m')
      return 20162;

   if (*(p1++)!='/')
      return 20163;
//m / 1 / 2 / 3
//0 1 2 3 4 5 6
   out2=mkey;
   while (p2=strchr(p1, '/')) {
      if (p1==p2) {
         err=20164;
         goto f_derive_xkey_EXIT1;
      }

      if ((err=f_parse_index_string_to_uint32_t_util(&index, (const char *)p1, p2-p1)))
         goto f_derive_xkey_EXIT1;

      if ((err=f_derive_xpriv_or_xpub_dynamic(&out1, NULL, NULL, out2, index, out_type&(~(DERIVE_XPRIV_XPUB_DYN_OUT_BASE58)))))
         goto f_derive_xkey_EXIT1;

      if (out2!=mkey)
         free(out2);

      p1=p2+1;

      out2=out1;

   }

   if ((val_sz+=(size_t)m_depth)>(size_t)p1) {

      if ((err=f_parse_index_string_to_uint32_t_util(&index, (const char *)p1, val_sz-(size_t)p1+1)))
         goto f_derive_xkey_EXIT1;

      if ((err=f_derive_xpriv_or_xpub_dynamic(out, NULL, NULL, out2, index, out_type)))
         goto f_derive_xkey_EXIT1;

   } else
      err=20167;

f_derive_xkey_EXIT1:
   if (out2!=mkey)
      free(out2);

   return err;
}
// 0 is valid
// otherwise error
int f_check_if_invalid_btc_public_key(uint8_t *public_key)
{
   int err;
   uint8_t *buf;
   char ch;
#define BTC_BUF_PK_SZ 65
   if (!(buf=malloc(BTC_BUF_PK_SZ)))
      return 20200;

   if ((ch=public_key[0])==0x04)
      memcpy(buf, public_key, BTC_BUF_PK_SZ);
   else if ((err=f_uncompress_elliptic_curve(buf, BTC_BUF_PK_SZ, NULL, MBEDTLS_ECP_DP_SECP256K1, public_key, 33)))
      goto f_check_if_invalid_btc_public_key_EXIT1;

   err=f_ecdsa_public_key_valid(MBEDTLS_ECP_DP_SECP256K1, (unsigned char *)buf, BTC_BUF_PK_SZ);

f_check_if_invalid_btc_public_key_EXIT1:
   free(memset(buf, 0, BTC_BUF_PK_SZ));
   return err;
#undef BTC_BUF_PK_SZ
}

