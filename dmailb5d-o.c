#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include "getln.h"
#include "alloc.h"
#include "open.h"
#include "scan.h"
#include "now.h"
#include "fmt.h"
#include "str.h"
#include "exit.h"
#include "readwrite.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "strerr.h"
#include "error.h"

#include "rijndael.h"
#include "pad.h"
#include "txtparse.h"
#include "mt19937.h"
#include "minilzo.h"


#define FATAL "ble: fatal:"

#define NULL 0

/* Work-memory needed for compression. Allocate memory in units
 * of `long' (instead of `char') to make sure it is properly aligned.
 */

#define HEAP_ALLOC(var,size) \
	long __LZO_MMODEL var [ ((size) + (sizeof(long) - 1)) / sizeof(long) ]
static HEAP_ALLOC(wrkmem,LZO1X_1_MEM_COMPRESS);


void die() { _exit(0); }


char ssoutbuf[1024];
//substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);

char ssinbuf[128];
//substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

void put(buf,len) char *buf; int len;
{
  buffer_put(buffer_1, buf, len);
}
void puts(s) char *s;
{
  buffer_puts(buffer_1, s);
}
void flush()
{
  buffer_flush(buffer_1);
}
void err(s) char *s;
{
  puts("-ERR ");
  puts(s);
  puts("\r\n");
  flush();
}

void die_nomem() { err("out of memory"); die(); }
void die_nomaildir() { err("this user has no $HOME/Maildir"); die(); }
void die_scan() { err("unable to scan $HOME/Maildir"); die(); }

void err_syntax() { err("syntax error"); }
void err_unimpl() { err("unimplemented"); }
void err_deleted() { err("already deleted"); }
void err_nozero() { err("messages are counted from 1"); }
void err_toobig() { err("not that many messages"); }
void err_nosuch() { err("unable to open that message"); }
void err_nounlink() { err("unable to unlink all deleted messages"); }


int safewrite(int fd,char *buf,unsigned int len)
{
  int w;
  w = timeoutwrite(60,fd,buf,len);
  if (w <= 0) strerr_die2sys(111,FATAL,"unable to write to network: ");
  return w;
}


char netwritespace[1024];
buffer netwrite = BUFFER_INIT(safewrite,1,netwritespace,sizeof netwritespace);
// char ssoutbuf[256];
// substdio ssout = SUBSTDIO_FDBUF(safewrite,1,ssoutbuf,sizeof ssoutbuf);
 
int saferead(fd,buf,len) int fd; char *buf; int len;
 {
   int r;
   //   substdio_flush(&ssout); //?
   r = read(fd,buf,len);
   if (r <= 0) _exit(0);
   return r;
 }

char netreadspace[1024];
buffer netread = BUFFER_INIT(saferead,1,netreadspace,sizeof netreadspace);
// char ssinbuf[512];
// substdio ssin = SUBSTDIO_FDBUF(saferead,0,ssinbuf,sizeof ssinbuf);

unsigned long getlen()
{
  unsigned long len = 0;
  char ch;
  for (;;) 
    { 
      //      substdio_get(&ssin,&ch,1);
      buffer_get(&netread, &ch, 1);
      if (ch == ':') return len;
      if (len > 200000000) ; // resources();
      len = 10 * len + (ch - '0');
    }
}
int getlines(stralloc *buf)
     /* reads a netstring followed by "\n" from fd 0 */
     /* returns this in s as a null-terminated string */
     /* (without \n) */
{
  unsigned long len;
  char c;
  
  len = getlen();
  // get data and ",\n"
  stralloc_readyplus(buf, len+2);
  buffer_get(&netread, buf->s, len+2);
  buf->len = len + 2;
} 

   

char *remotehost;
char *remoteinfo;
char *remoteip;
char *local;
stralloc failure = {0};

void byte_xor(char *s1, char *s2, char *out, unsigned int n)
{
  for (;;) 
    {
      if (!n) return; *out++ = *s1++ ^ *s2++; --n;
      if (!n) return; *out++ = *s1++ ^ *s2++; --n;
      if (!n) return; *out++ = *s1++ ^ *s2++; --n;
      if (!n) return; *out++ = *s1++ ^ *s2++; --n;
    }
}

void byte_Ixor(char *d, char *s, unsigned int n)
{
  for (;;) 
    {
      if (!n) return; *d++ ^= *s++; --n;
      if (!n) return; *d++ ^= *s++; --n;
      if (!n) return; *d++ ^= *s++; --n;
      if (!n) return; *d++ ^= *s++; --n;
    }
}

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
    strerr_die2sys(111, FATAL, "input data is not 128 Bit aligned");    
  if(l < 32)      // XXX: fixme
    strerr_die2sys(111, FATAL, "input data is < 32 bytes");    
  
  for(n = 16; n < l; n += 16)
    {
      stralloc_catb(p, &c[n], 16); 
      rijndaelDecrypt(&p->s[p->len-16]);
      byte_Ixor(&p->s[p->len-16], &c[n-16], 16);
    }

  return p->len;
} 

static int allwrite(int (*op)(),int fd,char *buf,unsigned int len)
{
  int w;

  while (len > 0) {
    w = op(fd,buf,len);
    if (w == -1) {
      if (errno == error_intr) continue;
      return -1; /* note that some data may have been written */
    }
    if (w <= 0) ; /* luser's fault */
    buf += w;
    len -= w;
  }
  return 0;
}

/* encrypt data and write it */
int cryptwrite(int fd, char *buf, unsigned int len)
{
  int w, r;
  stralloc out = {0};

  //  if(len % 16 != 0) /* XXX */
  //    strerr_die2sys(111, FATAL, "input data is not 128 Bit aligned");    

  //  rijndaelEncrypt_cbc(buf, len, &out);

  stralloc_ready(&out, len + len / 64 + 16 + 3);
  out.len = len + len / 64 + 16 + 3;

  r = lzo1x_1_compress(buf, len, out.s, &out.len, wrkmem);
  if (r == LZO_E_OK)
    //		printf("compressed %lu bytes into %lu bytes\n",
    ; //	(long) in_len, (long) out_len);
  else
    {
      /* this should NEVER happen */
      //		printf("internal error - compression failed: %d\n", r);
      return 2;
    }
  /* check for an incompressible block */

  w = timeoutwrite(1200, fd, out.s, out.len);

  alloc_free(out.s);

  if (w <= 0) 
    strerr_die2sys(111, FATAL, "unable to write to network: ");

  /* we cheat, since we have NOT written len bytes */
  return len;
}

void byte_fill(char *s, register unsigned int n, register char f)
{
  for (;;) {
    if (!n) break; *s++ = f; --n;
    if (!n) break; *s++ = f; --n;
    if (!n) break; *s++ = f; --n;
    if (!n) break; *s++ = f; --n;
  }
}

char cryptwritespace[1024*256];
buffer cwbuf = BUFFER_INIT(cryptwrite, 1, cryptwritespace, sizeof cryptwritespace);

/* fillbuffer with zeros to a multiple of a then flush */
int buffer_flushalign(buffer *s, int a)
{
  int p;
 
  if (!s->p) return 0;
  if(s->p % a != 0)
    {
      p = a - (s->p % a);
      byte_fill(s->x + s->p, p, 'X'); 
      s->p += p;
    }
  p = s->p;
  s->p = 0;
  return allwrite(s->op,s->fd,s->x,p);
}

void netstr_puts(stralloc *sa, char *s)
     /* write s as a netstring followed to netwrite */
     /* s is a null-terminated string */
{
  unsigned long len;

  len = str_len(s);
  stralloc_readyplus(sa, FMT_ULONG);
  len = fmt_ulong(&sa->s[sa->len], len);
  sa->len += len;
  stralloc_cats(sa, ":");
  stralloc_cats(sa, s);
  stralloc_cats(sa, ",");
}


/* clean cruft from Maildir/tmp */
void maildir_clean(tmpname)
stralloc *tmpname;
{
 DIR *dir;
 struct dirent *d;
 struct stat st;
 datetime_sec time;

 time = now();

 dir = opendir("tmp");
 if (!dir) return;

 while (d = readdir(dir))
  {
   if (d->d_name[0] == '.') continue;
   if (!stralloc_copys(tmpname,"tmp/")) break;
   if (!stralloc_cats(tmpname,d->d_name)) break;
   if (!stralloc_0(tmpname)) break;
   if (stat(tmpname->s,&st) == 0)
     if (time > st.st_atime + 129600)
       unlink(tmpname->s);
  }
 closedir(dir);
}

void send_mailfile(char *filename)
{
  int fd;
  char bspace[1024];
  buffer b;
  stralloc out = {0};
  char strnum[FMT_ULONG];
  struct stat st;
  
  /* find out filesize */
  if (stat(filename, &st) != 0)
    strerr_die3sys(111, FATAL, "unable to stat", filename);

  netstr_puts(&out, filename);
  
  strnum[fmt_ulong(strnum, st.st_size)] = 0;
  stralloc_cats(&out, strnum);
  stralloc_cats(&out, ":");

  fd = open_read(filename);
  if (fd == -1) 
    { 
      err_nosuch(filename); 
      return; 
    }
  
  buffer_init(&b, read, fd, bspace, sizeof bspace);

  buffer_put(&cwbuf, out.s, out.len);
  buffer_copy(&cwbuf, &b);
  buffer_puts(&cwbuf, ",");
  
  close(fd);
}

static int send_maildir(char *subdir)
{
  DIR *dir;
  struct dirent *d;
  unsigned int pos;
  struct stat st;
  struct stralloc filename = {0};

  dir = opendir(subdir);
  if (!dir)
    strerr_die3sys(111, FATAL, "unable to scan", subdir);
  
  while (d = readdir(dir))
    {
      if (d->d_name[0] == '.') continue;
      if (!stralloc_copys(&filename, subdir)) break;
      if (!stralloc_cats(&filename, "/")) break;
      if (!stralloc_cats(&filename, d->d_name)) break;
      if (!stralloc_0(&filename)) break;
      send_mailfile(filename.s);
    }
  
  closedir(dir);
  if (d) 
    strerr_die3sys(111, FATAL, "unable to scan", subdir);

  return 0;
}

int main(int argc, char *argv[])
{
  struct stat st;
  int i;
  stralloc key = {0};  stralloc tmp = {0};  stralloc out = {0};  stralloc decr = {0};  stralloc in = {0};

  /* seed some entropy into the MT */
  seedMT((long long) getpid () *
	 (long long) time(0) *
	 (long long) getppid() * 
	 (long long) random() * 
	 (long long) clock());


  //  sig_alarmcatch(die);
  // sig_pipeignore();

  stralloc_copys(&key, "geheim");  txtparse(&key);  pad(&key, 32);
  
   /* initialize rijndael */
  rijndaelKeySched(4, 8, key.s);
 
  if (!argv[1]) 
    die_nomaildir();
  
  if (chdir(argv[1]) == -1) 
    die_nomaildir();
  
  if (lzo_init() != LZO_E_OK)
    {
      //		printf("lzo_init() failed !!!\n");
      return 3;
    }

 
  /* clean cruft from Maildir/tmp */
  maildir_clean(&tmp);
  
  send_maildir("cur");
  send_maildir("new");

  buffer_flushalign(&cwbuf, 16);

  return 0;
}


/*************************************************************************
//
**************************************************************************/

int test()
{
	int r;
	lzo_uint in_len;
	lzo_uint out_len;
	lzo_uint new_len;

 
	//	in_len = IN_LEN;
	//byte_zero(in,in_len);

/*
 * Step 3: compress from `in' to `out' with LZO1X-1
 */

/*
 * Step 4: decompress again, now going from `out' to `in'
 */
	//	r = lzo1x_decompress(out,out_len,in,&new_len,NULL);
	//if (r == LZO_E_OK && new_len == in_len)
	  //		printf("decompressed %lu bytes back into %lu bytes\n",
	  //	(long) out_len, (long) in_len);
	  ;
	  //	else
	{
		/* this should NEVER happen */
	  //	printf("internal error - decompression failed: %d\n", r);
		return 1;
	}

	//	printf("\nminiLZO simple compression test passed.\n");
	return 0;
}

