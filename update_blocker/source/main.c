
#include "ps4.h"
char buf[200];


static int( * sceKernelDebugOutText)(int,
  const char * ) = NULL;
size_t page_size = 0x4000;


void * kernel_base = NULL;
int kpayload(struct thread * td) {
  kernel_base = & ((uint8_t * ) __readmsr(0xC0000082))[-0x1C0];

  struct ucred * cred = td -> td_proc -> p_ucred;
  cred -> cr_uid = 0;
  cred -> cr_ruid = 0;
  cred -> cr_rgid = 0;
  cred -> cr_groups[0] = 0;

  // escalate ucred privs, needed for access to the filesystem ie* mounting & decrypting files
  void * td_ucred = * (void ** )(((char * ) td) + 304); // p_ucred == td_ucred

  // sceSblACMgrIsSystemUcred
  uint64_t * sonyCred = (uint64_t * )(((char * ) td_ucred) + 96);
  * sonyCred = 0xffffffffffffffff;

  // sceSblACMgrGetDeviceAccessType
  uint64_t * sceProcType = (uint64_t * )(((char * ) td_ucred) + 88);
  * sceProcType = 0x3801000000000013; // Max access

  // sceSblACMgrHasSceProcessCapability
  uint64_t * sceProcCap = (uint64_t * )(((char * ) td_ucred) + 104);
  * sceProcCap = 0xffffffffffffffff; // Sce Process

  return 0;
}

int _main(struct thread * td) {
  UNUSED(td);
 

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
  sceKernelDebugOutText(0, "Block updates ...\n");
  touch_file("/update/PS4UPDATE.PUP");
  touch_file("/update/PS4UPDATE.PUP.net");
  touch_file("/update/PS4UPDATE.PUP.NET");
  if ((int)unmount("/update", 0x80000LL) < 0)
  {
	unmount("/update", 0);
  }
  sceKernelDebugOutText(0, "Blocked updates\n");
  printf_notification("Blocked updates");

  

  return 0;
}
