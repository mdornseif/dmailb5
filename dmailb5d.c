#include <unistd.h>              /* for close */
#include <pwd.h>                 /* for getpwuid */
#include <stdlib.h>              /* for random() */
#include <time.h>                /* time */
#include <sys/types.h>
#include <sys/stat.h>

#include <dirent.h>
#include "getln.h"
#include "alloc.h"
#include "open.h"
#include "scan.h"
#include "now.h"
#include "env.h"
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
#include "zlib.h"
#include "netstr.h"
#include "zlib.h"

#define FATAL "dmailb5d: fatal:"
#define WARN "dmailb5d: warning:"

/* move me to a header file */

#define stralloc_free(sa)  alloc_free((sa)->s); (sa)->s = (sa)->len = (sa)->a = 0;

void die() { _exit(0); }

/* compression functions */

unsigned long dmb_compress(char *dest, unsigned int *destLen, const char *source, unsigned long sourceLen)
{
  z_stream stream;
  int err;
  
  stream.next_in = (Bytef*)source;
  stream.avail_in = (uInt)sourceLen;
  stream.next_out = dest;
  stream.avail_out = (uInt)*destLen;
  if ((uLong)stream.avail_out != *destLen) return Z_BUF_ERROR;
  
  stream.zalloc = (alloc_func)0;
  stream.zfree = (free_func)0;
  stream.opaque = (voidpf)0;
  
  err = deflateInit(&stream, Z_DEFAULT_COMPRESSION);
  if (err != Z_OK) return err;
  
  err = deflate(&stream, Z_FINISH);
  if (err != Z_STREAM_END) {
    deflateEnd(&stream);
    return err == Z_OK ? Z_BUF_ERROR : err;
  }
  *destLen = stream.total_out;
  
  err = deflateEnd(&stream);
  return err;
}

/* compress and encrypt while writing */

/* encrypt data and write it */
int cryptwrite(int fd, char *buf, unsigned int len)
{
  int r;
  stralloc out1 = {0};
  stralloc out2 = {0};

  /* XXX: this uses FAR TOO MUCH memory and cpu by copying the data too much arround */

  /* get some space ready to put compressed data */
  stralloc_ready(&out1, len + len / 1000 + 12 + 1);
  out1.len = len + len / 1000 + 12 + 1;

  r = dmb_compress(out1.s, &out1.len, buf, len);
 
  netstr_write_stralloc(&out2, out1.s, out1.len);
  stralloc_free(&out1);

  /* pad to be 128 Bit / 16 byte aligned */
  stralloc_align(&out2, 16);
    
  stralloc_copyb(&out1, "P", 1);
  rijndaelEncrypt_cbc(out2.s, out2.len, &out1);
  stralloc_free(&out2);
  
  netstr_write_stralloc(&out2, out1.s, out1.len);

  if(timeoutwrite(1200, fd, out2.s, out2.len) != out2.len)
    strerr_die2sys(111, FATAL, "unable to write to network: ");
 
  stralloc_free(&out1);
  stralloc_free(&out2);
 
  /* we cheat, since we have NOT written len bytes */
  return len;
}


/* our funky crypto-compression-buffer is 256 bytes at the moment */ 

char cryptwritespace[1024*256];
buffer cwbuf = BUFFER_INIT(cryptwrite, 1, cryptwritespace, sizeof cryptwritespace);

/* send a single file by writing it to our special 
   crypto-compression-buffer */
int send_mailfile(char *filename)
{
  int fd;
  char readbspace[8192];
  buffer readb;
  char strnum[FMT_ULONG];
  struct stat st;
  
  /* find out filesize */
  if (stat(filename, &st) != 0)
    strerr_die4sys(111, FATAL, "unable to stat() ", filename, ": ");

  fd = open_read(filename);
  if (fd == -1) 
    {
      strerr_warn4(WARN, "unable to open(r) ", filename, ": ", 0);
      return -1; 
    }

  /* init a buffer for reading */
  buffer_init(&readb, read, fd, readbspace, sizeof readbspace);

  /* output filename */
  netstr_write_buf(&cwbuf, filename, str_len(filename));
  
  /* output the filelength to produce a netstring */
  if(buffer_put(&cwbuf, strnum, fmt_ulong(strnum, st.st_size)))
    strerr_die2sys(111, FATAL, "unable to write: ");
  if(buffer_put(&cwbuf, ":", 1))
    strerr_die2sys(111, FATAL, "unable to write: ");
  
  /* copy all data from file to the network */
  if(buffer_copy(&cwbuf, &readb))
    strerr_die2sys(111, FATAL, "unable to copy: ");
  if(buffer_puts(&cwbuf, ","))
    strerr_die2sys(111, FATAL, "unable to write: ");
  
  close(fd);
  return 0;
}


/* functions working with Maildirs */

/* clean cruft from Maildir/tmp */
void maildir_clean()
{
 DIR *dir;
 struct dirent *d;
 struct stat st;
 datetime_sec time;
 stralloc tmpname = {0};

 time = now();

 dir = opendir("tmp");
 if (!dir) return;

 while (d = readdir(dir))
  {
   if (d->d_name[0] == '.') continue;
   if (!stralloc_copys(&tmpname,"tmp/")) break;
   if (!stralloc_cats(&tmpname,d->d_name)) break;
   if (!stralloc_0(&tmpname)) break;
   if (stat(tmpname.s,&st) == 0)
     if (time > st.st_atime + 129600)
       unlink(tmpname.s);
  }
 closedir(dir);
 stralloc_free(&tmpname);
}

/* send all files in subdir */
void send_maildir(char *subdir)
{
  DIR *dir;
  struct dirent *d;
  struct stralloc filename = {0};

  dir = opendir(subdir);
  if (!dir)
    strerr_die4sys(111, FATAL, "unable to scan ", subdir, ": ");
  
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
    strerr_die4sys(111, FATAL, "unable to scan ", subdir, ": ");
}

int main(int argc, char *argv[])
{
  char *x; 
  stralloc key = {0};  
  
  /* seed some entropy into the MT */
  seedMT((long long) getpid () *
	 (long long) time(0) *
	 (long long) getppid() * 
	 (long long) random() * 
	 (long long) clock());
  
  // sig_alarmcatch(die);
  // sig_pipeignore();

  x = env_get("KEY");
  if (!x)
    strerr_die2x(100, FATAL, "$KEY not set");
  stralloc_copys(&key, x);  
  txtparse(&key);  
  stralloc_pad(&key, 32);
  
   /* initialize rijndael */
  rijndaelKeySched(4, 8, key.s);
  
  if (!argv[1]) 
    strerr_die2x(100, FATAL, "usage: dmailb5d Maildir");
  if (chdir(argv[1]) == -1) 
    strerr_die4sys(100, FATAL, "can't chdir() to ", argv[1], ": ");
    
  /* clean cruft from Maildir/tmp */
  maildir_clean("tmp");
  
  /* sent content of Maildir to the client */
  send_maildir("cur");
  send_maildir("new");

  buffer_puts(&buffer_1, "1:L,");

  buffer_flush(&cwbuf);

  return 0;
}
