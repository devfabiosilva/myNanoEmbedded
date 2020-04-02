/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdio.h>
#include <string.h>
#include "f_nano_crypto_util.h"

int main(int argc, char **argv)
{

   int err;
   char *p;
   uint8_t buf[512];

   if (argc==1) {

      printf(LICENSE);
      printf("\nConverts your hex string 32 bytes SEED to Bip39 or your Bip39 words to Nano SEED\n");
      printf("\nType:\n\texample4 seed <YOUR HEX STRING SEED>\n\texample4 bip39 <YOUR WORD LIST STRING>\n\n");

      return 0;

   }

   if (argc>3) {

      printf("\nToo many arguments\n");

      return 22;

   }

   p=NULL;
   err=0;

   if (strcmp("seed", argv[1])==0) {

      if (argc==2)
         p="Nano SEED";

      err=1;

   } else if (strcmp("bip39", argv[1])==0) {

      if (argc==2)
         p="Bip39 word list";

   } else {

      printf("\nError. Invalid option. Choose seed <YOUR SEED> or bip39 <YOUR BIP39 WORD LIST>\n\n");

      return 21;

   }

   if (p) {

      printf("\nError. MISSING: %s\n\n", p);

      return 23;

   }

   p=argv[2];

   if (err) {

      if (strnlen(p, 65)!=64) {

         printf("\nError. Invalid Nano SEED length. It must be 32 bytes long!\n\n");

         return 24;

      }

      if ((err=f_str_to_hex(buf+sizeof(buf)-64, p))) {

         printf("\nError when converting \"%s\" to raw hex stream %d\n\n", p, err);

         return err;

      }

      if (err=f_nano_seed_to_bip39((char *)buf, sizeof(buf)-64, NULL, buf+sizeof(buf)-64, BIP39_DICTIONARY_SAMPLE)) {

         printf("\nError when parse SEED to Bip39 in \"f_nano_seed_to_bip39\" %d\n", err);

         return err;

      }

      printf("\nSuccess. Your Bip39 for \"%s\" is \n\t\"%s\"\n\nKeep it safe !\n\n", p, buf);

      memset(buf, 0, sizeof(buf));

      return 0;

   }

   memset(buf, 0, sizeof(buf));

   if ((err=f_bip39_to_nano_seed(buf, (char *)strncpy((char *)(buf+32), p, sizeof(buf)-64), BIP39_DICTIONARY_SAMPLE))) {

      printf("\nError. Can't parse Bip39 word list \"%s\" to Nano SEED %d\n\n", p, err);

      return err;

   }

   printf("\nFound Nano SEED \"%s\" in Bip39 \"%s\"\n\nKeep it safe !!!\n\n", f_nano_key_to_str(buf+32, buf), p);

   memset(buf, 0, sizeof(buf));

   return 0;

}

