#include "stralloc.h"
#include "strerr.h"
#include "rijndael.h"
#include "mt19937.h"

static char rcsid[] = "$Id$";
static char rcsname[] = "$RCSname";

#define FATAL rcsname

  
/* rijndael CBC encryption */

int rijndaelEncrypt_cbc(char *p, unsigned int l, stralloc *c)
{
  unsigned int n;

  if(l % 16 != 0) /* XXX */
    strerr_die2sys(111, FATAL, "input data is not 128 Bit aligned");    
 
  /* fill the IV */
  stralloc_readyplus(c, 16);
  blockMT(&c->s[c->len], 16);
  c->len += 16;
  
  for(n = 0; n < l; n += 16)
    {
      stralloc_readyplus(c, 16);
      byte_xor(&p[n], &c->s[c->len-16], &c->s[c->len], 16);
      rijndaelEncrypt(&c->s[c->len]);
      c->len += 16;
    }

  return c->len;
} 

int rijndaelDecrypt_cbc(char *c, unsigned int l, stralloc *p)
{
  unsigned int n;

  /* if ciphertext is not a multiple of 128 Bits we have a problem */
  if(l % 16 != 0) // XXX: fixme
    strerr_die2x(111, FATAL, "input data is not 128 Bit aligned");    
  if(l < 32)      // XXX: fixme
    strerr_die2x(111, FATAL, "input data is < 32 bytes");    
  
  for(n = 16; n < l; n += 16)
    {
      stralloc_catb(p, &c[n], 16); 
      rijndaelDecrypt(&p->s[p->len-16]);
      byte_Ixor(&p->s[p->len-16], &c[n-16], 16);
    }

  return p->len;
} 

