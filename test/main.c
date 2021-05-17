//fri apr 23 21:34:27 -03 2021 sex abr 23 21:34:29 -03 2021 
#include <common_test.h>
#include <utilities_test.h>
#include <token_test.h>
#include <bitcoin_test.h>
#include <uncompress_ecc_test.h>
#include <nano_test.h>

#define INFO "\n\n***** %s *****\n"
int main (int argc, char **argv)
{
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
   parse_seed_to_json();

   TITLE_MSG("Finishing myNanoEmbedded library tests ...")

   end_tests();

   return 0;
}

