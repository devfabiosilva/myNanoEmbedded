/*
	AUTHOR: Fábio Pereira da Silva
	YEAR: 2019-20
	LICENSE: MIT
	EMAIL: fabioegel@gmail.com or fabioegel@protonmail.com
*/
//ter 24 mar 2020 02:39:28 -03 

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

   char buffer[1024];
   uint8_t rand[32];
   int err;

   printf(LICENSE);

   memset(rand, 0, sizeof(rand));

   printf("\nInitializing buffer value \"%s\"\n", f_nano_key_to_str(buffer, rand));

   f_random_attach(gen_rand_no_entropy);

   f_random(rand, sizeof(rand));

   printf("\nBuffer filled with a random value without any entropy check \"%s\"\n", f_nano_key_to_str(buffer, rand));

   printf("\nVerifying system entropy with attached random number generator. It can take a little longer depending your TRNG or PRNG\n");

   ENTROPY_BEGIN
   err=f_verify_system_entropy(F_ENTROPY_TYPE_PARANOIC, rand, sizeof(rand), 0);
   ENTROPY_END

   if (err)
      printf("\nError in \"f_verify_system_entropy\" %d\n", err);
   else {
      printf("\nBuffer value \"f_verify_system_entropy\" \"%s\"\n", f_nano_key_to_str(buffer, rand));
   }

   printf("\nHello World !\n");

   return 0;

}
