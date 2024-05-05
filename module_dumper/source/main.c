
#include "ps4.h"
char buf[200];

#define DT_DIR 0x000004
#define DT_REG 0x000008
#define DEC_SIZE 0x100000
static int( * sceKernelDebugOutText)(int,
  const char * ) = NULL;
size_t page_size = 0x4000;


void my_free(void *ptr, size_t size) {
    // Align size to page size
    size = (size + page_size - 1) & ~(page_size - 1);
 
    // Use munmap to my_free memory
    munmap(ptr, size);
}

void *my_malloc(size_t size) {
    // Align size to page size
    size = (size + page_size - 1) & ~(page_size - 1);

    // Use mmap to allocate memory
    void *ptr = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        sprintf(buf, "[-] Error: Cant mmap:  %s\n", strerror(errno));
        sceKernelDebugOutText(0, buf);
        return NULL; // mmap failed
    }
    return ptr;
}
void * kernel_base = NULL;
int kpayload(struct thread * td) {
  kernel_base = & ((uint8_t * ) __readmsr(0xC0000082))[-0x1C0];
  uint8_t *kernel_ptr  = (uint8_t *)kernel_base;
  //int (*kprintf)(const char *format, ...) =  (void*)(kernel_base+0x02FCBD0);
  //kprintf("Hello from Kernel\n");
  struct ucred * cred = td -> td_proc -> p_ucred;
 // kprintf("setting cr_uid ...\n");
  cred -> cr_uid = 0;
 // kprintf("setting cr_ruid ...\n");
  cred -> cr_ruid = 0;
 // kprintf("setting cr_rgid ...\n");
  cred -> cr_rgid = 0;
 // kprintf("setting cr_groups ...\n");
  cred -> cr_groups[0] = 0;

  // escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
  void * td_ucred = * (void ** )(((char * ) td) + 304); // p_ucred == td_ucred
 // kprintf("setting sceSblACMgrIsSystemUcred ...\n");

  // sceSblACMgrIsSystemUcred
  uint64_t * sonyCred = (uint64_t * )(((char * ) td_ucred) + 96);
  * sonyCred = 0xffffffffffffffff;

 // kprintf("setting ceSblACMgrGetDeviceAccessType ...\n");

  // sceSblACMgrGetDeviceAccessType
  uint64_t * sceProcType = (uint64_t * )(((char * ) td_ucred) + 88);
  * sceProcType = 0x3801000000000013; // Max access

 // kprintf("setting sceSblACMgrHasSceProcessCapability ...\n");

  // sceSblACMgrHasSceProcessCapability
  uint64_t * sceProcCap = (uint64_t * )(((char * ) td_ucred) + 104);
  * sceProcCap = 0xffffffffffffffff; // Sce Process

  //kprintf("returning from Kernel  ...\n");
  return 0;
}

int read_decrypt_segment_alt(int fd, uint64_t index, uint64_t offset, size_t size, uint8_t * out) {
  uint8_t * outPtr = out;
  uint64_t outSize = size;
  uint64_t realOffset = (index << 32) | offset;

  while (outSize > 0) {
    size_t bytes = (outSize > DEC_SIZE) ? DEC_SIZE : outSize;
    uint8_t * addr = (uint8_t * ) mmap(0, bytes, PROT_READ, MAP_PRIVATE | 0x80000, fd, realOffset);

    if (addr != MAP_FAILED) {
      memcpy(outPtr, addr, bytes);
      munmap(addr, bytes);
    } else {
      return 0;
    }

    outPtr += bytes;
    outSize -= bytes;
    realOffset += bytes;
  }

  return 1;
}

int is_segment_in_other_segment_alt(Elf64_Phdr * phdr, int index, Elf64_Phdr * phdrs, int num) {
  for (int i = 0; i < num; i += 1) {
    Elf64_Phdr * p = & phdrs[i];
    if (i != index)
      if (p -> p_filesz > 0)
        if ((phdr -> p_offset >= p -> p_offset) && ((phdr -> p_offset + phdr -> p_filesz) <= (p -> p_offset + p -> p_filesz)))
          return 1;
  }

  return 0;
}

SegmentBufInfo * parse_phdr_alt(Elf64_Phdr * phdrs, int num, int * segBufNum) {
  SegmentBufInfo * infos = (SegmentBufInfo * ) my_malloc(sizeof(SegmentBufInfo) * num);
  int segindex = 0;
  for (int i = 0; i < num; i += 1) {
    Elf64_Phdr * phdr = & phdrs[i];

    if (phdr -> p_filesz > 0) {
      if ((!is_segment_in_other_segment_alt(phdr, i, phdrs, num)) || (phdr -> p_type == 0x6fffff01)) {
        SegmentBufInfo * info = & infos[segindex];
        segindex += 1;
        info -> index = i;
        info -> bufsz = (phdr -> p_filesz + (phdr -> p_align - 1)) & (~(phdr -> p_align - 1));
        info -> filesz = phdr -> p_filesz;
        info -> fileoff = phdr -> p_offset;
        info -> enc = (phdr -> p_type != 0x6fffff01) ? 1 : 0;
      }
    }
  }
  * segBufNum = segindex;

  return infos;
}

void do_dump_alt(char * saveFile, int fd, SegmentBufInfo * segBufs, int segBufNum, Elf64_Ehdr * ehdr) {
  int sf = open(saveFile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
  if (sf != -1) {
    size_t elfsz = 0x40 + ehdr -> e_phnum * sizeof(Elf64_Phdr);
    write(sf, ehdr, elfsz);

    for (int i = 0; i < segBufNum; i += 1) {
      uint8_t * buf = (uint8_t * ) my_malloc(segBufs[i].bufsz);
      memset(buf, 0, segBufs[i].bufsz);
      if (segBufs[i].enc) {
        if (read_decrypt_segment_alt(fd, segBufs[i].index, 0, segBufs[i].filesz, buf)) {
          lseek(sf, segBufs[i].fileoff, SEEK_SET);
          write(sf, buf, segBufs[i].bufsz);
        }
      } else {
        lseek(fd, -segBufs[i].filesz, SEEK_END);
        read(fd, buf, segBufs[i].filesz);
        lseek(sf, segBufs[i].fileoff, SEEK_SET);
        write(sf, buf, segBufs[i].filesz);
      }
      my_free(buf, segBufs[i].bufsz);
    }
    close(sf);
  } else {
    sprintf(buf, "[-] Error: Cant dump: %s | %s\n", saveFile, strerror(errno));
    sceKernelDebugOutText(0, buf);
    printf_notification(buf);
  }
}

void decrypt_and_dump_self_alt(char * selfFile, char * saveFile) {
  int fd = open(selfFile, O_RDONLY, 0);
  if (fd != -1) {
    void * addr = mmap(0, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr != MAP_FAILED) {
      uint16_t snum = * (uint16_t * )((uint8_t * ) addr + 0x18);
      Elf64_Ehdr * ehdr = (Elf64_Ehdr * )((uint8_t * ) addr + 0x20 + snum * 0x20);

      // shdr fix
      ehdr -> e_shoff = ehdr -> e_shentsize = ehdr -> e_shnum = ehdr -> e_shstrndx = 0;

      Elf64_Phdr * phdrs = (Elf64_Phdr * )((uint8_t * ) ehdr + 0x40);

      int segBufNum = 0;
      SegmentBufInfo * segBufs = parse_phdr_alt(phdrs, ehdr -> e_phnum, & segBufNum);
      do_dump_alt(saveFile, fd, segBufs, segBufNum, ehdr);

      my_free(segBufs, sizeof(SegmentBufInfo) *segBufNum);
      munmap(addr, 0x4000);
    } else {
      sprintf(buf, "[-] Error: Cant mmap:  %s | %s\n", selfFile, strerror(errno));
      sceKernelDebugOutText(0, buf);
      printf_notification(buf);
    }
    close(fd);
  } else {
    sprintf(buf, "[-] Error: Cant open: %s | %s\n", selfFile, strerror(errno));
    sceKernelDebugOutText(0, buf);
    printf_notification(buf);
  }
}

void decrypt_self_to_elf(char * file, char * usb) {
  char * dot;

  // Check filename and open file
  dot = strrchr(file, '.');
  if (!dot) return;
  if (strcmp(dot, ".elf") &&
    strcmp(dot, ".self") &&
    strcmp(dot, ".sprx")) {
    return;
  }
  char name[1024];
  char usbdir[1024];

  strcpy(name, file);
  sprintf(usbdir, "%s/%s", usb, name + 2);

  decrypt_and_dump_self_alt(name + 1, usbdir);
}

int traverse_dir(char * base, char * usb, void( * handler)(char * , char * )) {
  char name[1024];
  char usbdir[1024];

  DIR * dir;
  struct dirent * entry;

  if (!(dir = opendir(base)))
    return 1;

  while ((entry = readdir(dir)) != NULL) {
    char * dname = entry -> d_name;
    switch (entry -> d_type) {
    case DT_DIR:
      if (!strcmp(dname, ".") ||
        !strcmp(dname, "..") ||
        !strcmp(dname, "cache0002") ||
        !strcmp(dname, "dev") ||
        !strcmp(dname, "mnt") ||
        !strcmp(dname, "preinst") ||
        !strcmp(dname, "preinst2") ||
        !strcmp(dname, "$RECYCLE.BIN") ||
        !strcmp(dname, "sandbox") ||
        !strcmp(dname, "system_data") ||
        !strcmp(dname, "system_tmp") ||
        !strcmp(dname, "user")) {
        continue;
      }

      snprintf(name, sizeof(name), "%s/%s", base, dname);

      if (!strcmp(dname, "lib") || !strcmp(dname, "sys"))
        sprintf(usbdir, "%s/%s/%s", usb, base + 2, dname);
      else
        sprintf(usbdir, "%s/%s", usb, base + 2);

      mkdir(usbdir, 0644);
      traverse_dir(name, usb, handler);
      break;

    case DT_REG:
      sprintf(name, "%s/%s", base, dname);
      handler(name, usb);
      break;
    }
  }
  closedir(dir);
  return 0;
}

int _main(struct thread * td) {
  UNUSED(td);
  char buf[255];

  char fw_version[6] = {
    0
  };
  char usb_name[7] = {
    0
  };
  char usb_path[13] = {
    0
  };
  char output_root[PATH_MAX] = {
    0
  };

  // Initialize PS4 Kernel, libc, and networking
  initKernel();
  initLibc();
  initSysUtil();

  // Load and resolve libkernel_sys library
  int libk = sceKernelLoadStartModule("libkernel_sys.sprx", 0, NULL, 0, 0, 0);
  RESOLVE(libk, sceKernelDebugOutText);

  // Output initialization messages
  if (sceKernelDebugOutText) {
    sceKernelDebugOutText(0, "==========================\n");
    sceKernelDebugOutText(0, "Hello From inside Shellcore!!!\n");
    sceKernelDebugOutText(0, "==========================\n");
  }

  //jailbreak();
  syscall(11, &kpayload, NULL);

  sprintf(buf, "kernel_base: %p\n", kernel_base);
  sceKernelDebugOutText(0, buf);
  printf_notification("kbase: %p, waiting 10 secs", kernel_base);
  sceKernelDebugOutText(0, "calling sleep\n");
  sceKernelSleep(10);
  sceKernelDebugOutText(0, "called sleep\n");
  sceKernelDebugOutText(0, "calling get_firmware_string\n");
  get_firmware_string(fw_version);
  sceKernelDebugOutText(0, "called get_firmware_string\n");

  sprintf(buf, "fw_version: %s\n", fw_version);
  sceKernelDebugOutText(0, buf);

  printf_notification("Running Module Dumper");
  wait_for_usb(usb_name, usb_path);
  sceKernelDebugOutText(0, "Found USB\n");

  sprintf(output_root, "%s/PS4", usb_path);
  mkdir(output_root, 0777);
  sprintf(output_root, "%s/%s", output_root, fw_version);
  mkdir(output_root, 0777);
  sprintf(output_root, "%s/modules", output_root);

  mkdir(output_root, 0777);

  printf_notification("USB device detected.\n\nStarting module dumping to %s.", usb_name);

  sprintf(buf, "Starting module dumping to %s.\n", usb_name);
  sceKernelDebugOutText(0, buf);

  traverse_dir("/", output_root, decrypt_self_to_elf);

  printf_notification("Modules dumped successfully!");
  sceKernelDebugOutText(0, "Modules dumped successfully!");

  return 0;
}