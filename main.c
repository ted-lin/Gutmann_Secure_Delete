#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>

   
#define SPC_WIPE_BUFSIZE 4096

static int spc_devrand_fd           = -1,
           spc_devrand_fd_noblock =   -1, 
           spc_devurand_fd          = -1;

void spc_make_fd_nonblocking(int fd) {
  int flags;
   
  flags = fcntl(fd, F_GETFL);  /* Get flags associated with the descriptor. */
  if (flags == -1) {
    perror("spc_make_fd_nonblocking failed on F_GETFL");
    exit(-1);
  }
  flags |= O_NONBLOCK;         
  /* Now the flags will be the same as before, except with O_NONBLOCK set.
   */
  if (fcntl(fd, F_SETFL, flags) == -1) {   
    perror("spc_make_fd_nonblocking failed on F_SETFL");
    exit(-1);
  }
}
   
void spc_rand_init(void) {
  spc_devrand_fd         = open("/dev/random",  O_RDONLY);
  spc_devrand_fd_noblock = open("/dev/random",  O_RDONLY);
  spc_devurand_fd        = open("/dev/urandom", O_RDONLY);
   
  if (spc_devrand_fd == -1 || spc_devrand_fd_noblock == -1) {
    perror("spc_rand_init failed to open /dev/random");
    exit(-1);
  }
  if (spc_devurand_fd == -1) {
    perror("spc_rand_init failed to open /dev/urandom");
    exit(-1);
  }
  spc_make_fd_nonblocking(spc_devrand_fd_noblock);
}
   
unsigned char *spc_rand(unsigned char *buf, size_t nbytes) {
  ssize_t       r;
  unsigned char *where = buf;
   
  if (spc_devrand_fd == -1 && spc_devrand_fd_noblock == -1 && spc_devurand_fd == -1)
    spc_rand_init(  );
  while (nbytes) {
    if ((r = read(spc_devurand_fd, where, nbytes)) == -1) {
      if (errno == EINTR) continue;
      perror("spc_rand could not read from /dev/urandom");
      exit(-1);
    }
    where  += r;
    nbytes -= r;
  }
  return buf;
}
   
unsigned char *spc_keygen(unsigned char *buf, size_t nbytes) {
  ssize_t       r;
  unsigned char *where = buf;
   
  if (spc_devrand_fd == -1 && spc_devrand_fd_noblock == -1 && spc_devurand_fd == -1)
    spc_rand_init(  );
  while (nbytes) {
    if ((r = read(spc_devrand_fd_noblock, where, nbytes)) == -1) {
      if (errno == EINTR) continue;
      if (errno == EAGAIN) break;
      perror("spc_rand could not read from /dev/random");
      exit(-1);
    }
    where  += r;
    nbytes -= r;
  }
  spc_rand(where, nbytes);
  return buf;
}
   
unsigned char *spc_entropy(unsigned char *buf, size_t nbytes) {
  ssize_t       r;
  unsigned char *where = buf;
   
  if (spc_devrand_fd == -1 && spc_devrand_fd_noblock == -1 && spc_devurand_fd == -1)
    spc_rand_init(  );
  while (nbytes) {
    if ((r = read(spc_devrand_fd, (void *)where, nbytes)) == -1) {
      if (errno == EINTR) continue;
      perror("spc_rand could not read from /dev/random");
      exit(-1);
    }
    where  += r;
    nbytes -= r;
  }
  return buf;
}

   
static int write_data(int fd, const void *buf, size_t nbytes) {
  size_t  towrite, written = 0;
  ssize_t result;
   
  do {
    if (nbytes - written > SSIZE_MAX) towrite = SSIZE_MAX;
    else towrite = nbytes - written;
    if ((result = write(fd, (const char *)buf + written, towrite)) >= 0)
      written += result;
    else if (errno != EINTR) return 0;
  } while (written < nbytes);
  return 1;
}
   
static int random_pass(int fd, size_t nbytes)
{
  size_t        towrite;
  unsigned char buf[SPC_WIPE_BUFSIZE];
   
  if (lseek(fd, 0, SEEK_SET) != 0) return -1;
  while (nbytes > 0) {
    towrite = (nbytes > sizeof(buf) ? sizeof(buf) : nbytes);
    spc_rand(buf, towrite);
    if (!write_data(fd, buf, towrite)) return -1;
    nbytes -= towrite;
  }
  fsync(fd);
  return 0;
}
   
static int pattern_pass(int fd, unsigned char *buf, size_t bufsz, size_t filesz) {
  size_t towrite;
   
  if (!bufsz || lseek(fd, 0, SEEK_SET) != 0) return -1;
  while (filesz > 0) {
    towrite = (filesz > bufsz ? bufsz : filesz);
    if (!write_data(fd, buf, towrite)) return -1;
    filesz -= towrite;
  }
  fsync(fd);
  return 0;
}
   
int spc_fd_wipe(int fd) {
  int           count, i, pass, patternsz;
  struct stat   st;
  unsigned char buf[SPC_WIPE_BUFSIZE], *pattern;
   
  static unsigned char single_pats[16] = {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
  };
  static unsigned char triple_pats[6][3] = {
    { 0x92, 0x49, 0x24 }, { 0x49, 0x24, 0x92 }, { 0x24, 0x92, 0x49 },
    { 0x6d, 0xb6, 0xdb }, { 0xb6, 0xdb, 0x6d }, { 0xdb, 0x6d, 0xb6 }
  };
   
  if (fstat(fd, &st) == -1) return -1;
  if (!st.st_size) return 0;
   
  for (pass = 0;  pass < 4;  pass++) {
	printf("pass %d\n", pass);
    if (random_pass(fd, st.st_size) == -1) return -1;
   }
  memset(buf, single_pats[5], sizeof(buf));
  if (pattern_pass(fd, buf, sizeof(buf), st.st_size) == -1) return -1;
  memset(buf, single_pats[10], sizeof(buf));
  if (pattern_pass(fd, buf, sizeof(buf), st.st_size) == -1) return -1;
   
  patternsz = sizeof(triple_pats[0]);
  for (pass = 0;  pass < 3;  pass++) {
	printf("pass %d\n", pass);
    pattern = triple_pats[pass];
    count   = sizeof(buf) / patternsz;
    for (i = 0;  i < count;  i++)
      memcpy(buf + (i * patternsz), pattern, patternsz);
    if (pattern_pass(fd, buf, patternsz * count, st.st_size) == -1) return -1;
  }
   
  for (pass = 0;  pass < sizeof(single_pats);  pass++) {
	printf("pass %d\n", pass);
    memset(buf, single_pats[pass], sizeof(buf));
    if (pattern_pass(fd, buf, sizeof(buf), st.st_size) == -1) return -1;
  }
   
  for (pass = 0;  pass < sizeof(triple_pats) / patternsz;  pass++) {
	printf("pass %d\n", pass);
    pattern = triple_pats[pass];
    count   = sizeof(buf) / patternsz;
    for (i = 0;  i < count;  i++)
      memcpy(buf + (i * patternsz), pattern, patternsz);
    if (pattern_pass(fd, buf, patternsz * count, st.st_size) == -1) return -1;
  }
   
  for (pass = 0;  pass < 4;  pass++) {
	printf("pass %d\n", pass);
    if (random_pass(fd, st.st_size) == -1) return -1;
	}
  return 0;
}
   
int spc_file_wipe(FILE *f) {
  return spc_fd_wipe(fileno(f));
}

int main(int argc, char* argv[]) {
	if(argv[1]) {
		FILE *f = fopen(argv[1], "rb+");
		spc_rand_init();
		spc_file_wipe(f);
		fclose(f);
	}
	return 0;
}
