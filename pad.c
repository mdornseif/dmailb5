/* $Id$
 *  --drt@ailis.de
 * 
 * $Log$
 *
 */

#include "stralloc.h"

static char rcsid[] = "$Id$";

/* pad a string by repeating it or cut it off */

long stralloc_pad(stralloc *sa, int len)
{
  int l;
  
  while(sa->len < len)
    {
      l = len - sa->len;
      if( l > sa->len) l = sa->len; 
      if(!stralloc_catb(sa, sa->s, l)) return -1;
    }
  sa->s[len] = '\0';
  sa->len = len;

  return len;
}


unsigned int stralloc_align(stralloc *sa, int a)
{
  unsigned int r;

  if(sa->len % a != 0)
    {
      r = a - (sa->len % a);
      byte_fill(sa->s + sa->len, r, 'X'); 
      sa->len += r;
    }
  return sa->len;
}
