#ifdef __aarch64__
typedef struct
  {
    unsigned long long int __ctx(fault_address);
    unsigned long long int __ctx(regs)[31];
    unsigned long long int __ctx(sp);
    unsigned long long int __ctx(pc);
    unsigned long long int __ctx(pstate);
    /* This field contains extension records for additional processor
       state such as the FP/SIMD state.  It has to match the definition
       of the corresponding field in the sigcontext struct, see the
       arch/arm64/include/uapi/asm/sigcontext.h linux header for details.  */
    unsigned char __reserved[4096] __attribute__ ((__aligned__ (16)));
  } mcontext_t;
#elif __ARM_ARCH
typedef struct
  {
    unsigned long int __ctx(trap_no);
    unsigned long int __ctx(error_code);
    unsigned long int __ctx(oldmask);
    unsigned long int __ctx(arm_r0);
    unsigned long int __ctx(arm_r1);
    unsigned long int __ctx(arm_r2);
    unsigned long int __ctx(arm_r3);
    unsigned long int __ctx(arm_r4);
    unsigned long int __ctx(arm_r5);
    unsigned long int __ctx(arm_r6);
    unsigned long int __ctx(arm_r7);
    unsigned long int __ctx(arm_r8);
    unsigned long int __ctx(arm_r9);
    unsigned long int __ctx(arm_r10);
    unsigned long int __ctx(arm_fp);
    unsigned long int __ctx(arm_ip);
    unsigned long int __ctx(arm_sp);
    unsigned long int __ctx(arm_lr);
    unsigned long int __ctx(arm_pc);
    unsigned long int __ctx(arm_cpsr);
    unsigned long int __ctx(fault_address);
  } mcontext_t;
#elif _MIPS_ARCH
#if _MIPS_SIM == _ABIO32
/* Earlier versions of glibc for mips had an entirely different
   definition of mcontext_t, that didn't even resemble the
   corresponding kernel data structure.  Fortunately, makecontext,
   [gs]etcontext et all were not implemented back then, so this can
   still be rectified.  */
typedef struct
  {
    unsigned int __ctx(regmask);
    unsigned int __ctx(status);
    greg_t __ctx(pc);
    gregset_t __ctx(gregs);
    fpregset_t __ctx(fpregs);
    unsigned int __ctx(fp_owned);
    unsigned int __ctx(fpc_csr);
    unsigned int __ctx(fpc_eir);
    unsigned int __ctx(used_math);
    unsigned int __ctx(dsp);
    greg_t __ctx(mdhi);
    greg_t __ctx(mdlo);
    unsigned long __ctx(hi1);
    unsigned long __ctx(lo1);
    unsigned long __ctx(hi2);
    unsigned long __ctx(lo2);
    unsigned long __ctx(hi3);
    unsigned long __ctx(lo3);
  } mcontext_t;
#else
typedef struct
  {
    gregset_t __ctx(gregs);
    fpregset_t __ctx(fpregs);
    greg_t __ctx(mdhi);
    greg_t __ctx(hi1);
    greg_t __ctx(hi2);
    greg_t __ctx(hi3);
    greg_t __ctx(mdlo);
    greg_t __ctx(lo1);
    greg_t __ctx(lo2);
    greg_t __ctx(lo3);
    greg_t __ctx(pc);
    unsigned int __ctx(fpc_csr);
    unsigned int __ctx(used_math);
    unsigned int __ctx(dsp);
    unsigned int __glibc_reserved1;
  } mcontext_t;
#endif
#endif