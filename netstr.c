#include "buffer.h"
#include "buffer_drt.h"
#include "fmt.h"
#include "strerr.h"
#include "stralloc.h"

static char rcsid[] = "$Id$";
static char rcsfile[] = "$RCSfile$";

/* reads the len of the next netstring from buffer b */
long netstr_getlen_buf(buffer *b)
{
  unsigned long len = 0;
  char ch;

  for (;;) 
    { 
      if(buffer_get(b, &ch, 1) != 1)
	strerr_die2(111, "fatal: can't read a byte single byte at ", rcsfile, 0);
      if (ch == ':') 
	return len;
      if (len > 200000000)
	strerr_die2(111, "fatal: there is a Netstring *far* to long comming in at ", rcsfile, 0);
      len = 10 * len + (ch - '0');
    }
}

/* reads a netstring from buf */
/* returns it in sa */
void netstr_read_buf(buffer *b, stralloc *sa)
{
  char ch = 0;
  unsigned long len;
 
  len = netstr_getlen_buf(b);
  if(!stralloc_readyplus(sa, len))
    strerr_die2(111, "fatal: out of memory at ", rcsfile, 0);
 
  buffer_getall(b, sa->s + sa->len, len);
  sa->len += len;
  buffer_get(b, &ch, 1);
  if(ch != ',')
    strerr_die2(111, "fatal: there is a Netstring not terminated by `,' at ", rcsfile, 0);
} 

/* reads the len of the next netstring from s, returns len
   and moves s foreward to the beginning of the data */
long netstr_getlen(char *s)
{
  unsigned long len = 0;

  for (;;) 
    { 
      if (*s == ':') 
	return len;
      if (len > 200000000)
	strerr_die2(111, "fatal: there is a Netstring *far* to long comming in at ", rcsfile, 0);
      len = 10 * len + (*s - '0');
      s++;
    }
}

/* write s of len l as a netstring to b */
void netstr_write_buf(buffer *b, const char *s, const unsigned int n)
{
  char strnum[FMT_ULONG];
  unsigned int l;

  l = fmt_ulong(strnum, n);
  buffer_put(b, strnum, l);
  buffer_put(b, s, n);
  buffer_put(b, ",", 1);
}

/* write s of len l as a netstring to sa */
void netstr_write_stralloc(stralloc *sa, const char *s, const unsigned int n)
{
  char strnum[FMT_ULONG];
  unsigned int l;

  l = fmt_ulong(strnum, n);
  stralloc_catb(sa, strnum, l);
  stralloc_cats(sa, ":");
  stralloc_catb(sa, s, n);
  stralloc_cats(sa, ",");
}
