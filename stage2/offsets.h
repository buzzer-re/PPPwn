/*
 * Copyright (C) 2024 Andy Nguyen
 *
 * This software may be modified and distributed under the terms
 * of the MIT license.  See the LICENSE file for details.
 */

#ifndef __OFFSETS_H__
#define __OFFSETS_H__


#if FIRMWARE == 850 // FW 8.50

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0

#define kdlsym_addr_printf 0xffffffff8235d570

#define kdlsym_addr_sysent 0xffffffff832fc5c0

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2 // Identical to 9.00

#define kdlsym_addr_copyin_patch1 0xffffffff825a4337
#define kdlsym_addr_copyin_patch2 0xffffffff825a4343

#define kdlsym_addr_copyout_patch1 0xffffffff825a4242
#define kdlsym_addr_copyout_patch2 0xffffffff825a424e

#define kdlsym_addr_copyinstr_patch1 0xffffffff825a47e3
#define kdlsym_addr_copyinstr_patch2 0xffffffff825a47ef
#define kdlsym_addr_copyinstr_patch3 0xffffffff825a4820


#elif FIRMWARE == 900 // FW 9.00

#if ENABLE_DEBUG_MENU
#define enable_data_mount_patch 0x0032079B
#define enable_fpkg_patch 0x003D7AFF
#define fake_free_patch 0x00FD3211
#define pkg_installer_patch 0x00A10A81
#define ext_hdd_patch 0x006180FD
#define debug_trophies_patch 0x00743299

#define sceKernelIsGenuineCEX 0x0016EAA4
#define sceKernelIsGenuineCEX_1 0x008621D4
#define sceKernelIsGenuineCEX_2 0x008AFBC2
#define sceKernelIsGenuineCEX_3 0x00A27BD4
#define dipsw_libSceDipsw 0x0016EAD2 
#define dipsw_libSceDipsw_1 0x00249F7B 
#define dipsw_libSceDipsw_2 0x00862202 
#define dipsw_libSceDipsw_3 0x00A27C02 
#define sys_debug_menu 0x0001D1C0
#define sys_debug_menu_1 0x0001D520
#endif

// libkernel_sys.srpx
#define _scePthreadAttrInit_offset 0x0014190
#define _scePthreadAttrSetstacksize_offset 0x00141B0
#define _scePthreadCreate_offset 0x00145D0
#define _thr_initial_offset 0x8E830

//kern
// kbase + offset (offsets are not in theflow format)
#define vm_map_protect_p 0x00080B8B
#define ptrace_p 0x41F4E5
#define ptrace_p2 0x41F9D1
#define disable_aslr_p 0x5F824
#define sceSblACMgrIsAllowedSystemLevelDebugging_p 0x0001D1C0
#define kemem_2 0x37BF44
#define kemem_1 0x37BF3C
#define vm_map_lock_offset 0x0007BA30
#define vm_map_insert_offset 0x0007CD80
#define vm_map_unlock_offset 0x0007BAA0
#define malloc_offset 0x00301B20
#define free_offset 0x00301CE0
#define vm_map_lock_read_offset 0x0007BB80
#define vm_map_unlock_read_offset 0x0007BBD0
#define vm_map_lookup_entry_offset 0x0007C1C0
#define M_TEMP_offset 0x015621E0 
#define proc_rmem_offset 0x0041EB00
#define vm_map_findspace_offset 0x0007EC40
#define vm_map_delete_offset 0x0007E680
#define create_thread_offset 0x001ED670
#define all_proc_offset 0x01B946E0
#define sys_dynlib_dlsym_p 0x0023B67F
#define sys_dynlib_dlsym_p2 0x00221B40

/* kernel offsets */

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0

#define kdlsym_addr_printf 0xffffffff822b7a30

#define kdlsym_addr_sysent 0xffffffff83300310

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff824716f7
#define kdlsym_addr_copyin_patch2 0xffffffff82471703

#define kdlsym_addr_copyout_patch1 0xffffffff82471602
#define kdlsym_addr_copyout_patch2 0xffffffff8247160e

#define kdlsym_addr_copyinstr_patch1 0xffffffff82471ba3
#define kdlsym_addr_copyinstr_patch2 0xffffffff82471baf
#define kdlsym_addr_copyinstr_patch3 0xffffffff82471be0


#elif (FIRMWARE == 903 || FIRMWARE == 904) // FW 9.03/9.04

#if FIRMWARE == 903

#if ENABLE_DEBUG_MENU

// ShellCore offsets
#define enable_data_mount_patch 0x00321F2B
#define enable_fpkg_patch 0x003DA06F
#define fake_free_patch 0x00FD5BD1
#define pkg_installer_patch 0x00A13101
#define ext_hdd_patch 0x0061A66D
#define debug_trophies_patch 0x00745809

#define sceKernelIsGenuineCEX 0x0016F014
#define sceKernelIsGenuineCEX_1 0x00864744
#define sceKernelIsGenuineCEX_2 0x008B2232
#define sceKernelIsGenuineCEX_3 0x00A2A254
#define dipsw_libSceDipsw 0x0016F042
#define dipsw_libSceDipsw_1 0x0024A4EB
#define dipsw_libSceDipsw_2 0x00864772
#define dipsw_libSceDipsw_3 0x00A2A282

// debug menu libkernel_sys.prx
#define sys_debug_menu 0x1D1C0 // Identical to 9.00
#define sys_debug_menu_1 0x1D520 // Identical to 9.00

#endif

// libkernel_sys.srpx
#define _scePthreadAttrInit_offset 0x0014190 // Identical to 9.00
#define _scePthreadAttrSetstacksize_offset 0x00141B0 // Identical to 9.00
#define _scePthreadCreate_offset 0x145D0 // Identical to 9.00
#define _thr_initial_offset 0x8E830 // Identical to 9.00

//kern
#define vm_map_protect_p 0x00080B8B // Identical to 9.00
#define ptrace_p 0x41D455
#define ptrace_p2 0x41D941
#define disable_aslr_p 0x5F824 // Identical to 9.00
#define sceSblACMgrIsAllowedSystemLevelDebugging_p 0x0001D1C0 // Identical to 9.00
#define kemem_2 0x37A144
#define kemem_1 0x37A13C
#define vm_map_lock_offset 0x0007BA30 // Identical to 9.00
#define vm_map_insert_offset 0x0007CD80 // Identical to 9.00
#define vm_map_unlock_offset 0x0007BAA0 // Identical to 9.00
#define malloc_offset 0x003017B0
#define free_offset 0x00301970
#define vm_map_lock_read_offset 0x0007BB80 // Identical to 9.00
#define vm_map_unlock_read_offset 0x0007BBD0 // Identical to 9.00
#define vm_map_lookup_entry_offset 0x0007C1C0 // Identical to 9.00
#define M_TEMP_offset 0x0155E1E0
#define proc_rmem_offset 0x0041CA70
#define vm_map_findspace_offset 0x0007EC40 // Identical to 9.00
#define vm_map_delete_offset 0x0007E680 // Identical to 9.00
#define create_thread_offset 0x001ED620
#define all_proc_offset 0x01B906E0
#define sys_dynlib_dlsym_p 0x0023B34F
#define sys_dynlib_dlsym_p2 0x00221810

#endif

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0 // Identical to 9.00

#define kdlsym_addr_printf 0xffffffff822b79e0

#define kdlsym_addr_sysent 0xffffffff832fc310

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9 // Identical to 9.00
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2 // Identical to 9.00

#define kdlsym_addr_copyin_patch1 0xffffffff82471377
#define kdlsym_addr_copyin_patch2 0xffffffff82471383

#define kdlsym_addr_copyout_patch1 0xffffffff82471282
#define kdlsym_addr_copyout_patch2 0xffffffff8247128e

#define kdlsym_addr_copyinstr_patch1 0xffffffff82471823
#define kdlsym_addr_copyinstr_patch2 0xffffffff8247182f
#define kdlsym_addr_copyinstr_patch3 0xffffffff82471860


#elif (FIRMWARE == 950 || FIRMWARE == 960) // FW 9.50 / 9.60

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff82405470

#define kdlsym_addr_sysent 0xffffffff832f92f0

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff82401f07
#define kdlsym_addr_copyin_patch2 0xffffffff82401f13

#define kdlsym_addr_copyout_patch1 0xffffffff82401e12
#define kdlsym_addr_copyout_patch2 0xffffffff82401e1e

#define kdlsym_addr_copyinstr_patch1 0xffffffff824023b3
#define kdlsym_addr_copyinstr_patch2 0xffffffff824023bf
#define kdlsym_addr_copyinstr_patch3 0xffffffff824023f0


#elif (FIRMWARE == 1000 || FIRMWARE == 1001) // FW 10.00/10.01

#if ENABLE_DEBUG_MENU
// ShellCore offsets
#if FIRMWARE == 1001
#define enable_data_mount_patch 0x0031b320 // 1
#define enable_fpkg_patch 0x003d26bf // 1
#define fake_free_patch 0x00fb08d9 // 1
#define pkg_installer_patch 0x009f1601 // 1
#define ext_hdd_patch 0x0060500d // 1

#define sceKernelIsGenuineCEX 0x0016b6a4
#define sceKernelIsGenuineCEX_1 0x008594c4
#define sceKernelIsGenuineCEX_2 0x008a8602
#define sceKernelIsGenuineCEX_3 0x00a080b4
#define dipsw_libSceDipsw 0x0016b6d2
#define dipsw_libSceDipsw_1 0x00247e5c
#define dipsw_libSceDipsw_2 0x008594f2
#define dipsw_libSceDipsw_3 0x00a080e2
#else // FIRMWARE == 1000
#define enable_data_mount_patch 0x0031b310
#define enable_fpkg_patch 0x003d26af
#define fake_free_patch 0x00fb08b9
#define pkg_installer_patch 0x009f15e1
#define ext_hdd_patch 0x00604ffd

#define sceKernelIsGenuineCEX 0x0016b694
#define sceKernelIsGenuineCEX_1 0x008594b4
#define sceKernelIsGenuineCEX_2 0x008a85f2
#define sceKernelIsGenuineCEX_3 0x00a08094
#define dipsw_libSceDipsw 0x0016b6c2
#define dipsw_libSceDipsw_1 0x00247e4c
#define dipsw_libSceDipsw_2 0x008594e2
#define dipsw_libSceDipsw_3 0x00a080c2
#endif

// debug menu libkernel_sys.prx
#define sys_debug_menu   0x1ce50
#define sys_debug_menu_1 0x1d1b0
#endif

// libkernel_sys.srpx 
#define _scePthreadAttrInit_offset 0x13e20
#define _scePthreadAttrSetstacksize_offset 0x13e40
#define _scePthreadCreate_offset 0x14260
#define _thr_initial_offset 0x8e830

//kern
#define vm_map_protect_p 0x39207B
#define ptrace_p 0x44E625
#define ptrace_p2 0x44EB11
#define disable_aslr_p 0x3BF3A4
#define sceSblACMgrIsAllowedSystemLevelDebugging_p 0x4497F0
#define kemem_2 0x33B114
#define kemem_1 0x33B10C

#define vm_map_lock_offset 0x38CF20
#define vm_map_insert_offset 0x38E270
#define vm_map_unlock_offset 0x38CF90
#define malloc_offset 0x109A60
#define free_offset 0x109C20
#define vm_map_lock_read_offset 0x38D070
#define vm_map_unlock_read_offset 0x38D0C0
#define vm_map_lookup_entry_offset 0x38D6B0
#define M_TEMP_offset 0x1532C00
#define proc_rmem_offset  0x44DC40
#define vm_map_findspace_offset 0x390130
#define vm_map_delete_offset 0x38FB70
#define create_thread_offset 0x182F0
#define all_proc_offset 0x22D9B40 // Address not in memory ?
#define sys_dynlib_dlsym_p 0x19025f
#define sys_dynlib_dlsym_p2 0x1bea40

/* kernel offsets */

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff822c50f0

#define kdlsym_addr_sysent 0xffffffff83302d90

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff82672f67
#define kdlsym_addr_copyin_patch2 0xffffffff82672f73

#define kdlsym_addr_copyout_patch1 0xffffffff82672e72
#define kdlsym_addr_copyout_patch2 0xffffffff82672e7e

#define kdlsym_addr_copyinstr_patch1 0xffffffff82673413
#define kdlsym_addr_copyinstr_patch2 0xffffffff8267341f
#define kdlsym_addr_copyinstr_patch3 0xffffffff82673450


#elif (FIRMWARE == 1050 || FIRMWARE == 1070 || FIRMWARE == 1071) // FW 10.50 / 10.70 / 10.71

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff82650e80

#define kdlsym_addr_sysent 0xffffffff833029c0

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff822d75b7
#define kdlsym_addr_copyin_patch2 0xffffffff822d75c3

#define kdlsym_addr_copyout_patch1 0xffffffff822d74c2
#define kdlsym_addr_copyout_patch2 0xffffffff822d74ce

#define kdlsym_addr_copyinstr_patch1 0xffffffff822d7a63
#define kdlsym_addr_copyinstr_patch2 0xffffffff822d7a6f
#define kdlsym_addr_copyinstr_patch3 0xffffffff822d7aa0


#define all_proc_offset 0x2269f30
#define disable_aslr_p  0x345e04
#define kemem_1         0x428a2c
#define kemem_2         0x428a34



#define vm_map_lock_offset          0x476180
#define vm_map_insert_offset        0x4774d0
#define vm_map_unlock_offset        0x4761f0
#define malloc_offset               0x36e120
#define free_offset                 0x36e2e0
#define vm_map_lock_read_offset     0x4762d0
#define vm_map_unlock_read_offset   0x476320
#define vm_map_lookup_entry_offset  0x476910
#define M_TEMP_offset               0x1a5fe30
#define proc_rmem_offset            0x4244a0
#define vm_map_findspace_offset     0x479390
#define vm_map_delete_offset        0x478dd0
#define create_thread_offset        0x3384e0



#if MODULE_DUMPER

#define sceSblACMgrHasMmapSelfCapability 0x1f44e0
#define sceSblACMgrIsAllowedToMmapSelf   0x1f4500
#define sceSblAuthMgrIsLoadable          0x19e151
#define depth_patch                      0xdaa46

#endif

#elif FIRMWARE == 1100 // FW 11.00

#define kdlsym_addr_Xfast_syscall 0xffffffff822001c0
#define kdlsym_addr_printf 0xffffffff824fcbd0

#define kdlsym_addr_sysent 0xffffffff83301760

#define kdlsym_addr_amd_syscall_patch1 0xffffffff82200490
#define kdlsym_addr_amd_syscall_patch2 0xffffffff822004b5
#define kdlsym_addr_amd_syscall_patch3 0xffffffff822004b9
#define kdlsym_addr_amd_syscall_patch4 0xffffffff822004c2

#define kdlsym_addr_copyin_patch1 0xffffffff824de037
#define kdlsym_addr_copyin_patch2 0xffffffff824de043

#define kdlsym_addr_copyout_patch1 0xffffffff824ddf42
#define kdlsym_addr_copyout_patch2 0xffffffff824ddf4e

#define kdlsym_addr_copyinstr_patch1 0xffffffff824de4e3
#define kdlsym_addr_copyinstr_patch2 0xffffffff824de4ef
#define kdlsym_addr_copyinstr_patch3 0xffffffff824de520

/*=================== POrt these =======================*/

#if ENABLE_DEBUG_MENU
// ShellCore offsets
#define enable_data_mount_patch 0x31F070// 1
#define enable_fpkg_patch 0x3D7C9F // 1
#define fake_free_patch 0x0FC8439 // 1
#define pkg_installer_patch 0xA06C11 // 1
#define ext_hdd_patch 0x60E17D // 1

#define sceKernelIsGenuineCEX 0x16B664 //
#define sceKernelIsGenuineCEX_1 0x086BD24 //
#define sceKernelIsGenuineCEX_2 0x08BC022 //
#define sceKernelIsGenuineCEX_3 0x0A1D6C4//
#define dipsw_libSceDipsw 0x016B692 // 
#define dipsw_libSceDipsw_1 0x249E0C //
#define dipsw_libSceDipsw_2 0x086BD52 //
#define dipsw_libSceDipsw_3 0xA1D6F2 // 
// debug menu libkernel_sys.prx
#define sys_debug_menu   0x1D100
#define sys_debug_menu_1 0x1D460
#endif

// libkernel_sys.srpx 
#define _scePthreadAttrInit_offset 0x14010 
#define _scePthreadAttrSetstacksize_offset 0x14030
#define _scePthreadCreate_offset 0x14450
#define _thr_initial_offset 0x8E830

//kern
#define vm_map_protect_p 0x35C8EC
#define ptrace_p 0x00384285
#define ptrace_p2 0x00384771
#define disable_aslr_p 0x003B11A4
#define sceSblACMgrIsAllowedSystemLevelDebugging_p 0x003D0DE0
#define kemem_2 0x00245EE4
#define kemem_1 0x00245EDC

#define vm_map_lock_offset  0x00357760
#define vm_map_insert_offset 0x00358AB0
#define vm_map_unlock_offset  0x003577D0
#define malloc_offset 0x001A4220
#define free_offset 0x001A43E0
#define vm_map_lock_read_offset 0x003578B0
#define vm_map_unlock_read_offset 0x00357900
#define vm_map_lookup_entry_offset 0x00357EF0
#define M_TEMP_offset 0x015415B0
#define proc_rmem_offset  0x003838A0
#define vm_map_findspace_offset 0x0035A970
#define vm_map_delete_offset 0x0035A3B0
#define create_thread_offset 0x00295170
#define all_proc_offset 0x022D0A98

#if MODULE_DUMPER
#define sceSblACMgrHasMmapSelfCapability 0x003D0E50
#define sceSblACMgrIsAllowedToMmapSelf 0x003D0E70
#define sceSblAuthMgrIsLoadable 0x00157F91
#define depth_patch 0x0028FF26
#endif



#else

#error "Invalid firmware"

#endif

#define kdlsym(sym) (kaslr_offset + kdlsym_addr_##sym)

#endif
