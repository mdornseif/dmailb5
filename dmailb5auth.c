/* $Id: dmailb5auth.c,v 1.1 2000/05/19 14:04:35 drt Exp $
 *   --drt@ailis.de
 *
 * I don't belive there is anything like interlectual property 
 *
 * this does the authentication part of the dmailb5 
 * protocol - it should be run under tcpserver.
 * 
 * you might find more information at http://rc23.cx/
 *
 * $Log: dmailb5auth.c,v $
 * Revision 1.1  2000/05/19 14:04:35  drt
 * Initial revision
 * 
 */

#include <pwd.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc.h"
#include "buffer.h"
#include "byte.h"
#include "env.h"
#include "fmt.h"
#include "now.h"
#include "open.h"
#include "pathexec.h"
#include "readclose.h"
#include "readwrite.h"
#include "stralloc.h"
#include "strerr.h"
#include "timeoutread.h"
#include "timeoutwrite.h"
#include "uint32.h"
#include "uint64.h"

#include "netstr.h"
#include "txtparse.h"
#include "pad.h"
#include "rijndael.h"

static char rcsid[] = "$Id: dmailb5auth.c,v 1.1 2000/05/19 14:04:35 drt Exp $";

#define FATAL "dmailb5auth: fatal: "
char PID[FMT_ULONG];

char strnum[FMT_ULONG];
char *maildir;

void die_nomem() 
{  
  strerr_die3x(111, FATAL, PID, " no memory"); 
}

void die_usage() 
{ 
  strerr_die1x(100, "dmailb5auth: usage: dmailb5auth Maildir/ child"); 
}

int saferead(int fd, char *buf, unsigned int len)
{
  int w;
  
  w = timeoutread(1200, fd, buf, len);
  if (w <= 0) 
    strerr_die3sys(111, FATAL, PID, " unable to read from network: ");
  return w;
}

char netreadspace[256];
buffer netread = BUFFER_INIT(saferead, 0, netreadspace, sizeof netreadspace);

/* get key for username */
void get_key(stralloc *key, char *username)
{
  char *x;
  int fd;
  int r;
  struct passwd *pass;

  x = env_get("KEY");
  if (x)
    {
      /* $KEY is set, we are running in single user mode */
      if(chdir(maildir) == -1)
	strerr_die5sys(111, FATAL, PID, " can't chdir() to ", maildir, ": ");
      
      stralloc_copys(key, x);
      txtparse(key);  
      stralloc_pad(key, 32);
    }
  else
    {
      /* key is set, we are running in multi user mode */
      pass = getpwnam(username);
      if(pass == NULL)
	strerr_die5sys(100, FATAL, PID, " can't getpwnam() for ", 
		       username, ": ");
      
      /* drop privileges while reading*/
      if(seteuid(pass->pw_uid) == -1) 
	strerr_die3sys(111, FATAL, PID, " can't seteuid(): ");
      
      if(chdir(pass->pw_dir) == -1)
	strerr_die5sys(111, FATAL, PID, " can't chdir() to ", pass->pw_dir, ": ");

      fd = open_read(".dmailbkey");
      if(fd == -1)
	strerr_die5sys(100, FATAL, PID, " can't open .dmailbkey in ", 
		       pass->pw_dir, ": ");
      
      r = readclose(fd, key, 32);
      if(r == -1)
	strerr_die5sys(111, FATAL, PID, " can't read from .dmailbkey in ", pass->pw_dir, ": ");
      
      /* get privileges back to chroo()t */
      if(setuid(getuid()) == -1) 
	strerr_die3sys(111, FATAL, PID, " can't setuid(getuid()): ");
      
      if(chdir(maildir) == -1)
	strerr_die5sys(111, FATAL, PID, " can't chdir() to ", maildir, ": ");
      
      if(chroot(".") == -1)
	strerr_die3sys(111, FATAL, PID, " can't chroot(\".\"): ");
      
      /* drop privileges permanently*/
      if(seteuid(pass->pw_uid) == -1) 
	strerr_die3sys(111, FATAL, PID, " can't seteuid(): ");

      txtparse(key);  
      if(!stralloc_pad(key, 32)) die_nomem();
      if(!stralloc_0(key)) die_nomem();
    }      
}

int main(int argc, char **argv)
{
  char *cookie;
  char buf[16]; 
  char strnum[FMT_ULONG];
  int r;
  stralloc key = {0}; 
  stralloc sa = {0};
  stralloc username = {0};
  uint32 linespeed = 0xffffffff;
  uint64 tmp;

  PID[fmt_ulong(PID, getpid())] = 0;

  /* XXX: we should set a alarm signal to timeout */
  //  sig_alarmcatch(die);
 
  if(argc < 4)
    die_usage();
  
  maildir = *(argv+1);
  
  /* create a uniqe cookie, this does not have to 
     contain entropy, it just has to be uniqe */
  byte_copy(&tmp, 8, PID);
  tmp ^= (uint64)now();
  tmp ^= (uint64)getppid() << 48; 
  cookie = (char *) &tmp;

  /* create our banner */
  stralloc_copys(&sa, "you talk of peace and prepare for war\n");
  stralloc_cats(&sa, "v1 gzip rijndael blocksize 1024\n");
  stralloc_catb(&sa, cookie, 8);

  /* print banner */ 
  r = timeoutwrite(12, 1, sa.s, sa.len);
  
    /* read username and \0-terminate it */
  if(netstr_read_buf(&netread, &username) == -1)
    strerr_die3sys(111, FATAL, PID, " unable to read netstring from network: ");  
  if(!stralloc_0(&username)) 
    die_nomem();

  /* get the key from ~/.dmailbkey or enviroment, chdir() to
     ~/Maildir/ and then chroot() and drop uid */
  get_key(&key, username.s);

  /* initialize rijndael */
  rijndaelKeySched(4, 8, key.s);

  /* read encrypted cookie and linespeed from client and decrypt it */ 
  if(buffer_get(&netread, buf, 16) != 16)
    strerr_die3sys(111, FATAL, PID, " can't read encrypted answer from client (timeout?): ");  
  rijndaelDecrypt(buf);

  /* check if cookie was ok */
  if(byte_diff(buf, 8, cookie))
      strerr_die5x(111, FATAL, PID, "user ", username.s, " didn't get my cookie back");

  /* get linespeed */
  uint32_unpack(&buf[8], &linespeed);
  strnum[fmt_ulong(strnum, linespeed)] = 0;
  
  /* do logging */
  buffer_puts(buffer_2, "dmailbauth: ");
  buffer_puts(buffer_2, PID);
  buffer_puts(buffer_2, " user ");
  buffer_puts(buffer_2, username.s);
  buffer_puts(buffer_2, " connected with ");
  buffer_puts(buffer_2, strnum);
  buffer_puts(buffer_2, "bps\n");
  buffer_flush(buffer_2);
  
  /* start client */
  if (!pathexec_env("KEY", key.s)) 
    die_nomem();
  if (!pathexec_env("LINESPEED", strnum)) 
    die_nomem();
  pathexec(argv+2);
  
  /* we shouldn't get here */
  strerr_die5sys(111, FATAL, PID, " unable to run ", *(argv+2), ": ");

  return 111;
}
