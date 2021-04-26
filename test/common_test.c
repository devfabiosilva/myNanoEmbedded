#include "common_test.h"

static char msgbuffer[BUF_MSG_SZ];
char *msgbuf()
{
   return msgbuffer;
}

void clear_msgbuf()
{
   memset(msgbuffer, 0, sizeof(msgbuffer));
}

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

