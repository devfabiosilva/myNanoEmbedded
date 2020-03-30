/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/

#include <stdio.h>
#include <string.h>
#include "f_nano_crypto_util.h"

void gen_rand_no_entropy(void *output, size_t output_len)
{
   FILE *f;
   size_t rnd_sz, left;

   if (!(f=fopen("/dev/urandom", "r")))
      return;

   rnd_sz=0;
   left=output_len;

   while ((rnd_sz+=fread(output+rnd_sz, 1, left, f))<output_len)
      left-=rnd_sz;

   fclose(f);

   return;

}

int main(int argc, char *argv[])
{

   int err, i;
   NANO_SEED SEED, temp;
   NANO_PRIVATE_KEY_EXTENDED PRIVATE_KEY;
   NANO_PUBLIC_KEY_EXTENDED PUBLIC_KEY;
   char buffer[1024];

   printf(LICENSE);

   f_random_attach(gen_rand_no_entropy);

   printf("\nGenerating a SEED. It can take a little longer.\nTry to move the mouse, open a program, play a music to increase entropy ;)\n");

   if (err=f_generate_nano_seed(SEED, F_ENTROPY_TYPE_PARANOIC)) {

      printf("\nError \"f_generate_nano_seed\" %d\nCould not generate SEED. Aborting ...\n", err);

      return 1;

   }

   printf("\nSEED \"%s\" successfully generated. (DON'T TELL IT TO ANYBODY).\n", f_nano_key_to_str(buffer, SEED));

   if (err=f_nano_seed_to_bip39(buffer, sizeof(buffer), NULL, SEED, BIP39_DICTIONARY_SAMPLE)) {

      printf("\nError when parse SEED to Bip39 in \"f_nano_seed_to_bip39\" %d\n", err);

      return 4;

   }

   printf("****************************** YOUR NANO SEED IN ENCODED BIP 39 (DON'T TELL IT TO ANYONE) **********************************************\n\n");
   printf("BIP39 =\"%s\"\n\n KEEP IT IN A SAFE PLACE !!!\n\n", buffer);
   printf("****************************** ========================================================== **********************************************\n\n");

   memcpy(temp, SEED, sizeof(SEED));

   for (i=0;i<8;i++) {

      if (err=f_seed_to_nano_wallet(PRIVATE_KEY, PUBLIC_KEY, temp, (uint32_t)i)) {

         printf("\nError when extracting \"f_seed_to_nano_wallet\" %d\n", err);

         return 2;

      }

      printf("\nWALLET NUMBER %d\n", i);
      printf("-----------------------------------------------------------\n");

      printf("\nPRIVATE KEY = \"%s\" (DON'T TELL IT TO ANYBODY)\n", f_nano_key_to_str(buffer, PRIVATE_KEY));
      printf("\nPUBLIC KEY = \"%s\"\n", f_nano_key_to_str(buffer, PUBLIC_KEY));

      if (err=pk_to_wallet(buffer, NANO_PREFIX, PUBLIC_KEY)) {

         printf("\nError when parsing PUBLIC KEY to Base32 encoded string in \"pk_to_wallet\" %d\n", err);

         return 3;

      }

      printf("NANO Wallet %s\n", buffer);
      printf("============================================================\n");

      memcpy(temp, SEED, sizeof(SEED));

   }

   return 0;

}

