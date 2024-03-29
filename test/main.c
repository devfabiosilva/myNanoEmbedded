//fri apr 23 21:34:27 -03 2021
#include <common_test.h>
#include <utilities_test.h>
#include <token_test.h>
#include <bitcoin_test.h>
#include <uncompress_ecc_test.h>
#include <nano_test.h>

#define INFO "\n\n***** %s *****\n"
int main (int argc, char **argv)
{
   extern char welcome[] asm("_binary_welcome_txt_start");
   extern char welcome_end[] asm("_binary_welcome_txt_end");
   const size_t welcome_sz=welcome_end-welcome;

   TITLE_MSG("Initiating myNanoEmbedded library tests ...")

   INFO_MSG_FMT(INFO, "Initiating non deterministic token generator tests ...")
   token_test();

   INFO_MSG_FMT(INFO, "Testing uncompress elliptic curve for Bitcoin ...")
   uncompress_eliptic_curve_test();

   INFO_MSG_FMT(INFO, "Initiating Bitcoin Base58 tests for address ...")
   bitcoin_address_test();

   INFO_MSG_FMT(INFO, "Initiating utilities tests ...")
   url_decode_test();
   password_strength_test();

   INFO_MSG_FMT(INFO, "Initiating Nano cryptocurrency tests ...")
   nano_address_test();
   nano_seed_test();
   nano_block_test();
   nano_json_string_test();
   nano_encrypted_stream_test();
   parse_seed_to_json_test();
   nano_p2pow_test();
   verify_signature_test();
   sign_nano_block_test();
   balance_test();
   brainwallet_test();

   INFO_MSG_FMT(INFO, "Initiating mbedTLS tests ...")
   nano_embedded_mbedtls_bn_test();
   check_mbedTLS_mpi_size_test();
   xpriv_xpub_test();
   check_ec_secret_key_valid_test();
   check_ec_public_key_valid();

   TITLE_MSG("Finishing myNanoEmbedded library tests ...")

   printf("\n%.*s\n", (int)welcome_sz, welcome);

   end_tests();

   return 0;
}

