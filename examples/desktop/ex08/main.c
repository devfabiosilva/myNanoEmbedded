/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

// sab 11 abr 2020 01:09

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "f_nano_crypto_util.h"

#define USAGE "\
USAGE:\n\
======\n\t\
example8 <YOUR BRAIN WALLET> <SALT OF YOUR BRAIN WALLET>\n\n"

int main(int argc, char **argv)
{

   int err;
   char *msg;
   uint8_t seed[32];
   char mens[768];

   if (argc==1) {

      printf(LICENSE);
      printf(USAGE);

      return 0;

   }

   if (argc==2) {

      printf("\nERROR: Missing \"salt\" of your Brain Wallet\n\n");

      return -11;

   }

   if (argc>3) {

      printf("\nERROR: Too many arguments\n\n");

      return -12;

   }

   if ((err=f_extract_seed_from_brainwallet(seed, &msg, F_BRAIN_WALLET_PERFECT, (const char *)argv[1], (const char *)argv[2]))) {

      printf("\nError when extract NANO Seed in brain wallet %d\n", err);
      printf("\nWith message %s\n\n", msg);
      printf("\n\tHINT 1: Try to increase words or put some extra symbols or number or even capital letters\n");
      printf("\n\tHINT 2: Increase salt length including also extra symbols\n\n");

      return err;

   }

   printf("\nSUCCESS\nDon't tell any data here (SEED, Bip39, salt or even your brain wallet text) to ANYBODY !!!!");
   printf("\nYour Nano SEED \"%s\"\n", f_nano_key_to_str(mens, (unsigned char *)seed));
   printf("\nWith a estimated time to a Bitcoin antminer with 110TH/s to crack this Brain Wallet with bruteforce attack: %s\n", msg);

   if (err=f_nano_seed_to_bip39(mens, sizeof(mens), NULL, seed, BIP39_DICTIONARY_SAMPLE)) {

      printf("\nError when parse SEED to Bip39 in \"f_nano_seed_to_bip39\" %d\n", err);

      return err;

   }

   printf("\nYour Bip39 equivalent: \"%s\"\n", mens);

   printf("\n\nFinally HELLO WORLD !!!\n\n");

   memset(seed, 0, sizeof(seed));
   memset(mens, 0, sizeof(mens));

   return err;

}


