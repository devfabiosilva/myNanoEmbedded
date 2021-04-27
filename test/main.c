//fri apr 23 21:34:27 -03 2021 sex abr 23 21:34:29 -03 2021 
#include "common_test.h"
#include "token_test.h"
#include "bitcoin_test.h"
#include "uncompress_ecc_test.h"

//gcc -o test main.c ../src/ctest/asserts.c -I../include -I../include/sodium -I../include/ctest -L../lib -lnanocrypto1 -lsodium -fsanitize=leak,address
//gcc -o test main.c ../src/ctest/asserts.c bitcoin_test.c common_test.c uncompress_ecc_test.c -I../include -I../include/sodium -I../include/ctest -lsodium -lnanocrypto1 -Wall -L../lib

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

   end_tests();

   return 0;
}

